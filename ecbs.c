#include "ecbs.h"

#include <crc32.h>
#include <byteorder.h>

#include <stdarg.h>

typedef struct EcbsPacketView {
    EcbsRequestToken token;
    uint16_t tid;
    uint16_t data_id;
    uint8_t const* payload;
    uint16_t payload_size;
} EcbsPacketView;

static bool _is_broadcast_addr(EcbsAddr const addr);
static bool _is_token_equal(EcbsRequestToken const a, EcbsRequestToken const b);
static struct EcbsEndpoint* _find_endpoint(struct Ecbs* ecbs, EcbsDataId data_id);
static int _send_packet(struct Ecbs* ecbs, uint8_t pd, uint16_t tid, uint16_t data_id,
    uint8_t const* payload, uint16_t payload_size);
static int _send_proto_err(struct Ecbs* ecbs, uint16_t tid, uint16_t data_id, enum EcbsProtoErr err_code);
static int _send_app_err_code(struct Ecbs* ecbs, uint16_t tid, uint16_t data_id, uint8_t err_code);
static int _handle_read_write(struct Ecbs* ecbs, struct EcbsPacketView const* req, uint64_t now);
static int _handle_write_no_answer(struct Ecbs* ecbs, struct EcbsPacketView const* req);
static int _handle_frame(struct Ecbs* ecbs, uint16_t size, uint64_t now);
static int _receive(struct Ecbs* ecbs, uint64_t now);
static int _send_step(struct Ecbs* ecbs);

enum {
    ECBS__PD_DIR_MASK = 0x80,
    ECBS__PD_DIR_IS_REQ = 0x80,
    ECBS__PD_TYPE_MASK = 0x0F,
    ECBS__PD_TYPE_WRITE = 0x00,
    ECBS__PD_TYPE_WRITE_NO_ANSW = 0x01,
    ECBS__PD_TYPE_READ = 0x02,
    ECBS__PD_TYPE_PUB_DATA = 0x03,
    ECBS__PD_TYPE_APP_ERR = 0x0E,
    ECBS__PD_TYPE_PROTO_ERR = 0x0F,

    ECBS__PACKET_PD_POS = 0,
    ECBS__PACKET_ADDR_POS = 1,
    ECBS__PACKET_TID_POS = 2,
    ECBS__PACKET_DATA_ID_POS = 4,
    ECBS__PACKET_PAYLOAD_POS = 6,
    ECBS__CRC_SIZE = 4,

    ECBS__READ_CHUNK_SIZE = 32,
    ECBS__APP_ERR_DESC_SIZE = 128,

    ECBS__STD_DATA_ID__RESET = 65280,
};

static bool _is_broadcast_addr(EcbsAddr const addr) {
    return ECBS__BROADCAST_ADDR == addr;
}

static bool _is_token_equal(EcbsRequestToken const a, EcbsRequestToken const b) {
    return (a.pd == b.pd) && (a.crc32 == b.crc32);
}

static struct EcbsEndpoint* _find_endpoint(struct Ecbs* const ecbs, EcbsDataId const data_id) {
    for (int i = 0; i < ECBS__MAX_ENDPOINTS; i++) {
        struct EcbsEndpoint* const ep = &ecbs->endpoints[i];
        if (ep->is_used && (data_id == ep->id)) {
            return ep;
        }
    }

    return NULL;
}

/// @brief Build answer packet in tx_buf and start send. The answer deduplication state
/// is managed by the caller: answer_size is not touched here.
/// @param[in] payload may be NULL if payload_size is zero, or if the payload
/// is already placed in tx_buf at #ECBS__PACKET_PAYLOAD_POS.
static int _send_packet(struct Ecbs* const ecbs, uint8_t const pd, uint16_t const tid, uint16_t const data_id,
    uint8_t const* payload, uint16_t const payload_size) {
    int rc = 0;

    uint8_t* const buf = ecbs->tx_buf;
    buf[ECBS__PACKET_PD_POS] = pd;
    buf[ECBS__PACKET_ADDR_POS] = ecbs->addr;
    u16_to_le(&buf[ECBS__PACKET_TID_POS], tid);
    u16_to_le(&buf[ECBS__PACKET_DATA_ID_POS], data_id);

    if ((NULL != payload) && (0 < payload_size)) {
        memmove(&buf[ECBS__PACKET_PAYLOAD_POS], payload, payload_size);
    }

    uint16_t const crc_pos = ECBS__PACKET_PAYLOAD_POS + payload_size;
    u32_to_le(&buf[crc_pos], crc32__ieee(buf, crc_pos));

    uint16_t const packet_size = crc_pos + ECBS__CRC_SIZE;
    int const frame_size = framer7b__encode_in_place(buf, packet_size, sizeof(ecbs->tx_buf));
    ASSERTf(0 < frame_size, ER_1, "Fail to encode answer packet: %i", frame_size);

    ecbs->send_ptr = 0;
    ecbs->send_total = (uint16_t)frame_size;
    ecbs->state = ECBS_STATE__SEND;

 finally:

    return rc;
}

/// @brief Send PROTO_ERR answer. It is not stored as the request answer(dedup),
/// the pending request state is not touched, the stored answer is discarded.
static int _send_proto_err(struct Ecbs* const ecbs, uint16_t const tid, uint16_t const data_id,
    enum EcbsProtoErr const err_code) {
    int rc = 0;

    uint8_t const payload[1] = {(uint8_t)err_code};

    ecbs->answer_size = 0;
    TRY(_send_packet(ecbs, ECBS__PD_TYPE_PROTO_ERR, tid, data_id, payload, sizeof(payload)));

 finally:

    return rc;
}

/// @brief Send APP_ERR answer with one byte error_code and empty description,
/// complete the pending request and store the answer for deduplication.
static int _send_app_err_code(struct Ecbs* const ecbs, uint16_t const tid, uint16_t const data_id,
    uint8_t const err_code) {
    int rc = 0;

    uint8_t const payload[1] = {err_code};

    ecbs->pending_ep = ECBS__NO_PENDING_EP;
    TRY(_send_packet(ecbs, ECBS__PD_TYPE_APP_ERR, tid, data_id, payload, sizeof(payload)));
    ecbs->answer_size = ecbs->send_total;

 finally:

    return rc;
}

static int _handle_read_write(struct Ecbs* const ecbs, struct EcbsPacketView const* const req, uint64_t const now) {
    int rc = 0;

    uint8_t const type = req->token.pd & ECBS__PD_TYPE_MASK;
    bool const is_read = ECBS__PD_TYPE_READ == type;

    if ((is_read && (0 < req->payload_size)) || (ECBS__MAX_PAYLOAD_SIZE < req->payload_size)) {
        LOG_DBGf("Invalid payload size: type=%u size=%u", type, req->payload_size);
        TRY(_send_proto_err(ecbs, req->tid, req->data_id, ECBS_PROTO_ERR__INVALID_PAYLOAD_SIZE));
        goto finally;
    }

    if (0 == req->tid) {
        LOG_DBGf("Zero transaction_id: type=%u data_id=%u", type, req->data_id);
        TRY(_send_proto_err(ecbs, req->tid, req->data_id, ECBS_PROTO_ERR__INVALID_TRANSACTION_ID));
        goto finally;
    }

    if (ECBS_STATE__WAIT_ANSWER == ecbs->state) {
        if (req->tid == ecbs->last_tid) {
            if (req->token.crc32 == ecbs->last_request_token.crc32) {
                LOG_DBGf("Retry of the pending request, keep waiting: tid=%u", req->tid);
                goto finally;
            }

            LOG_DBGf("Transaction conflict, pending terminated: tid=%u", req->tid);
            ecbs->pending_ep = ECBS__NO_PENDING_EP;
            TRY(_send_proto_err(ecbs, req->tid, req->data_id, ECBS_PROTO_ERR__TRANSACTION_CONFLICT));
            goto finally;
        }

        LOG_DBGf("New request while pending, pending terminated: old_tid=%u new_tid=%u", ecbs->last_tid, req->tid);
    }
    else if (req->tid == ecbs->last_tid) {
        if (req->token.crc32 == ecbs->last_request_token.crc32) {
            if (0 < ecbs->answer_size) {
                LOG_DBGf("Resend the stored answer: tid=%u", req->tid);
                ecbs->send_ptr = 0;
                ecbs->send_total = ecbs->answer_size;
                ecbs->state = ECBS_STATE__SEND;
                goto finally;
            }

            // Retry after the slave side timeout, re-process the request.
        }
        else {
            LOG_DBGf("Transaction conflict with the last answered request: tid=%u", req->tid);
            TRY(_send_proto_err(ecbs, req->tid, req->data_id, ECBS_PROTO_ERR__TRANSACTION_CONFLICT));
            goto finally;
        }
    }

    // Commit the request as the current one.
    ecbs->last_request_token = req->token;
    ecbs->last_tid = req->tid;
    ecbs->last_data_id = req->data_id;
    ecbs->answer_size = 0;
    ecbs->tl_request = now;
    ecbs->pending_ep = ECBS__NO_PENDING_EP;

    struct EcbsEndpoint* const ep = _find_endpoint(ecbs, req->data_id);
    if ((NULL == ep) || (is_read && (NULL == ep->read)) || ((!is_read) && (NULL == ep->write))) {
        uint8_t const err_code = (NULL == ep) ? ECBS_APP_ERR__NO_DATA_ID : ECBS_APP_ERR__NO_OPERATION;
        LOG_DBGf("No endpoint operation: data_id=%u err=%u", req->data_id, err_code);
        TRY(_send_app_err_code(ecbs, req->tid, req->data_id, err_code));
        goto finally;
    }

    ecbs->pending_ep = (uint8_t)(ep - ecbs->endpoints);
    ecbs->state = ECBS_STATE__WAIT_ANSWER;

    int cb_rc = 0;
    if (is_read) {
        cb_rc = ep->read(req->data_id, req->token, ep->user_data);
    }
    else {
        cb_rc = ep->write(req->data_id, req->token, true, req->payload, req->payload_size, ep->user_data);
    }

    if (ECBS_STATE__SEND == ecbs->state) {
        // The application already queued the answer inside the callback.
        goto finally;
    }

    if (0 > cb_rc) {
        LOG_DBGf("Endpoint callback failed: data_id=%u rc=%i", req->data_id, cb_rc);
        TRY(_send_app_err_code(ecbs, req->tid, req->data_id, (uint8_t)(-cb_rc)));
        goto finally;
    }

    // Deferred answer, keep waiting in ECBS_STATE__WAIT_ANSWER.

 finally:

    return rc;
}

static int _handle_write_no_answer(struct Ecbs* const ecbs, struct EcbsPacketView const* const req) {
    int rc = 0;

    if (0 != req->tid) {
        LOG_DBGf("Drop WRITE_NO_ANSW with non-zero transaction_id: tid=%u data_id=%u", req->tid, req->data_id);
        goto finally;
    }

    if (ECBS__MAX_PAYLOAD_SIZE < req->payload_size) {
        LOG_DBGf("Drop WRITE_NO_ANSW with too big payload: size=%u", req->payload_size);
        goto finally;
    }

    struct EcbsEndpoint* const ep = _find_endpoint(ecbs, req->data_id);
    if ((NULL == ep) || (NULL == ep->write)) {
        LOG_DBGf("No endpoint for WRITE_NO_ANSW: data_id=%u", req->data_id);
        goto finally;
    }

    int const cb_rc = ep->write(req->data_id, req->token, false, req->payload, req->payload_size, ep->user_data);
    if (0 != cb_rc) {
        LOG_DBGf("WRITE_NO_ANSW endpoint callback failed: data_id=%u rc=%i", req->data_id, cb_rc);
    }

 finally:

    return rc;
}

static int _handle_frame(struct Ecbs* const ecbs, uint16_t const size, uint64_t const now) {
    int rc = 0;

    uint8_t* const buf = framer7b_receiver__buf(&ecbs->framer);

    if (ECBS__MIN_PACKET_SIZE > size) {
        LOG_DBGf("Drop packet, too small: %u", size);
        goto finally;
    }

    uint16_t const body_size = size - ECBS__CRC_SIZE;
    uint32_t const crc_recv = u32_from_le(&buf[body_size]);
    uint32_t const crc_calc = crc32__ieee(buf, body_size);
    if (crc_recv != crc_calc) {
        LOG_DBGf("Drop packet, crc mismatch: recv=%08X calc=%08X", crc_recv, crc_calc);
        goto finally;
    }

    uint8_t const pd = buf[ECBS__PACKET_PD_POS];
    if (ECBS__PD_DIR_IS_REQ != (pd & ECBS__PD_DIR_MASK)) {
        LOG_DBGf("Drop packet, not a request: pd=%02X", pd);
        goto finally;
    }

    ecbs->tl_master_activity = now;

    uint8_t const addr = buf[ECBS__PACKET_ADDR_POS];
    bool const is_broadcast = _is_broadcast_addr(addr);
    if ((ecbs->addr != addr) && !is_broadcast) {
        goto finally;
    }

    struct EcbsPacketView const req = {
        .token = {
            .pd = pd,
            .crc32 = crc_recv,
        },
        .tid = u16_from_le(&buf[ECBS__PACKET_TID_POS]),
        .data_id = u16_from_le(&buf[ECBS__PACKET_DATA_ID_POS]),
        .payload = &buf[ECBS__PACKET_PAYLOAD_POS],
        .payload_size = body_size - ECBS__PACKET_PAYLOAD_POS,
    };

    uint8_t const type = pd & ECBS__PD_TYPE_MASK;
    switch (type) {
    case ECBS__PD_TYPE_WRITE:
    case ECBS__PD_TYPE_READ:
        if (is_broadcast) {
            LOG_DBGf("Drop READ/WRITE to broadcast addr: tid=%u data_id=%u", req.tid, req.data_id);
            break;
        }
        rc = _handle_read_write(ecbs, &req, now);
        break;
    case ECBS__PD_TYPE_WRITE_NO_ANSW:
        rc = _handle_write_no_answer(ecbs, &req);
        break;
    default:
        LOG_DBGf("Drop packet, unsupported request type: %u", type);
        break;
    }

 finally:

    return rc;
}

static int _receive(struct Ecbs* const ecbs, uint64_t const now) {
    int rc = 0;
    uint8_t chunk[ECBS__READ_CHUNK_SIZE] = {0};

    if (ECBS_STATE__WAIT_ANSWER == ecbs->state) {
        struct EcbsEndpoint const* const ep = &ecbs->endpoints[ecbs->pending_ep];
        if (now - ecbs->tl_request >= ep->timeout_ms) {
            LOG_WRNf("Answer timeout: data_id=%u", ep->id);
            ecbs->pending_ep = ECBS__NO_PENDING_EP;
            ecbs->state = ECBS_STATE__RECEIVE;
        }
    }

    while (true) {
        int const nread = ecbs->read(chunk, sizeof(chunk));
        if (0 > nread) {
            rc = nread;
            LOG_ERRf("Fail to read from transport: %i", nread);
            goto finally;
        }
        if (0 == nread) {
            break;
        }

        ecbs->tl_receive = now;

        for (int i = 0; i < nread; i++) {
            int const frame_size = framer7b_receiver__push(&ecbs->framer, chunk[i]);
            if (0 < frame_size) {
                TRY_PASS(_handle_frame(ecbs, (uint16_t)frame_size, now));
                if (ECBS_STATE__SEND == ecbs->state) {
                    // The rest of the chunk is dropped, the next frame will be resynced by the framer.
                    goto finally;
                }
            }
        }
    }

 finally:

    return rc;
}

static int _send_step(struct Ecbs* const ecbs) {
    int rc = 0;

    while (ecbs->send_ptr < ecbs->send_total) {
        int const nwritten = ecbs->write(&ecbs->tx_buf[ecbs->send_ptr], ecbs->send_total - ecbs->send_ptr);
        if (0 > nwritten) {
            rc = nwritten;
            LOG_ERRf("Fail to write to transport: %i", nwritten);
            goto finally;
        }
        if (0 == nwritten) {
            // Transport cannot accept more data now, retry on the next process call.
            goto finally;
        }
        ecbs->send_ptr += (uint16_t)nwritten;
    }

    if (NULL != ecbs->get_write_status) {
        enum EcbsWriteStatus const status = ecbs->get_write_status();
        switch (status) {
        case ECBS_WRITE_STATUS__COMPLETED:
            break;
        case ECBS_WRITE_STATUS__PROCEEDED:
            // Still transmitting, poll again on the next process call.
            goto finally;
        case ECBS_WRITE_STATUS__FAILED:
            rc = ER_IO;
            LOG_ERR("Write status: FAILED");
            goto finally;
        default:
            rc = ER_PROTO_INTERNAL;
            LOG_ERRf("Unknown write status: %i", (int)status);
            goto finally;
        }
    }

    ecbs->state = (ECBS__NO_PENDING_EP != ecbs->pending_ep) ? ECBS_STATE__WAIT_ANSWER : ECBS_STATE__RECEIVE;

 finally:

    if (0 != rc) {
        // Drop the frame, the master will retry the request.
        ecbs->state = (ECBS__NO_PENDING_EP != ecbs->pending_ep) ? ECBS_STATE__WAIT_ANSWER : ECBS_STATE__RECEIVE;
    }

    return rc;
}

int ecbs__init(struct Ecbs* const ecbs, EcbsAddr const addr, uint64_t (*const get_time_ms)(void),
    int (*const read)(uint8_t* buf, uint16_t buf_size), int (*const write)(uint8_t const* data, uint16_t ndata),
    enum EcbsWriteStatus (*const get_write_status)(void)) {
    int rc = 0;

    memset(ecbs, 0, sizeof(*ecbs));
    ecbs->addr = addr;
    ecbs->read = read;
    ecbs->write = write;
    ecbs->get_time_ms = get_time_ms;
    ecbs->get_write_status = get_write_status;
    ecbs->state = ECBS_STATE__RECEIVE;
    ecbs->pending_ep = ECBS__NO_PENDING_EP;

    TRY(framer7b_receiver__init(&ecbs->framer, ecbs->rx_buf, sizeof(ecbs->rx_buf)));

 finally:

    return rc;
}

int ecbs__announce(struct Ecbs* const ecbs) {
    int rc = 0;

    ASSERT(ECBS_STATE__RECEIVE == ecbs->state, ER_BUSY);

    TRY(_send_packet(ecbs, ECBS__PD_TYPE_WRITE, 0, ECBS__STD_DATA_ID__RESET, NULL, 0));
    ecbs->answer_size = 0;

 finally:

    return rc;
}

int ecbs__register_endpoint(struct Ecbs* const ecbs, EcbsDataId const id, uint16_t const timeout_ms,
    void* const user_data, EcbsEndpointRead const read_callback, EcbsEndpointWrite const write_callback) {
    int rc = 0;

    ASSERTf(0 != timeout_ms, ER_INVAL, "timeout_ms cannot be zero: data_id=%u", id);
    ASSERTf((NULL != read_callback) || (NULL != write_callback), ER_INVAL,
        "At least one callback required: data_id=%u", id);
    ASSERTf(NULL == _find_endpoint(ecbs, id), ER_ALREADY, "Endpoint already registered: data_id=%u", id);

    struct EcbsEndpoint* ep = NULL;
    for (int i = 0; i < ECBS__MAX_ENDPOINTS; i++) {
        if (!ecbs->endpoints[i].is_used) {
            ep = &ecbs->endpoints[i];
            break;
        }
    }
    ASSERTf(NULL != ep, ER_NO_MEM, "No free endpoint slot: data_id=%u", id);

    ep->is_used = true;
    ep->id = id;
    ep->user_data = user_data;
    ep->read = read_callback;
    ep->write = write_callback;
    ep->timeout_ms = timeout_ms;

 finally:

    return rc;
}

int ecbs__get_tl_master_activity(struct Ecbs const* const ecbs, uint64_t* const result) {
    *result = ecbs->tl_master_activity;

    return 0;
}

int ecbs__send_write_answer(struct Ecbs* const ecbs, EcbsRequestToken const token) {
    int rc = 0;

    ASSERT(ECBS_STATE__SEND != ecbs->state, ER_BUSY);
    ASSERT(ECBS_STATE__WAIT_ANSWER == ecbs->state, ER_TIMEDOUT);
    ASSERT(_is_token_equal(token, ecbs->last_request_token), ER_INVAL);
    ASSERT(ECBS__PD_TYPE_WRITE == (token.pd & ECBS__PD_TYPE_MASK), ER_INVAL);

    ecbs->pending_ep = ECBS__NO_PENDING_EP;
    TRY(_send_packet(ecbs, ECBS__PD_TYPE_WRITE, ecbs->last_tid, ecbs->last_data_id, NULL, 0));
    ecbs->answer_size = ecbs->send_total;

 finally:

    return rc;
}

int ecbs__send_read_answer(struct Ecbs* const ecbs, EcbsRequestToken const token, uint8_t const* const data,
    uint16_t const data_size) {
    int rc = 0;

    ASSERT(ECBS_STATE__SEND != ecbs->state, ER_BUSY);
    ASSERT(ECBS_STATE__WAIT_ANSWER == ecbs->state, ER_TIMEDOUT);
    ASSERT(_is_token_equal(token, ecbs->last_request_token), ER_INVAL);
    ASSERT(ECBS__PD_TYPE_READ == (token.pd & ECBS__PD_TYPE_MASK), ER_INVAL);
    ASSERT((NULL != data) || (0 == data_size), ER_INVAL);
    ASSERTf(ECBS__MAX_PAYLOAD_SIZE >= data_size, ER_ENT_TOO_BIG, "Answer data too big: %u", data_size);

    ecbs->pending_ep = ECBS__NO_PENDING_EP;
    TRY(_send_packet(ecbs, ECBS__PD_TYPE_READ, ecbs->last_tid, ecbs->last_data_id, data, data_size));
    ecbs->answer_size = ecbs->send_total;

 finally:

    return rc;
}

int ecbs__send_app_error_answer(struct Ecbs* const ecbs, EcbsRequestToken const token, uint8_t const error_code,
    char const* const fmt, ...) {
    int rc = 0;

    ASSERT(ECBS_STATE__SEND != ecbs->state, ER_BUSY);
    ASSERT(ECBS_STATE__WAIT_ANSWER == ecbs->state, ER_TIMEDOUT);
    ASSERT(_is_token_equal(token, ecbs->last_request_token), ER_INVAL);

    ASSERT(ECBS__MAX_PAYLOAD_SIZE >= 3, ER_ENT_TOO_BIG);

    // The payload is built directly in tx_buf: [error_code][description + NULL].
    uint8_t* const payload = &ecbs->tx_buf[ECBS__PACKET_PAYLOAD_POS];
    payload[0] = error_code;
    uint16_t payload_size = 1;

    if (NULL != fmt) {
        uint16_t desc_cap = ECBS__APP_ERR_DESC_SIZE - 1;
        if (2 + desc_cap > ECBS__MAX_PAYLOAD_SIZE) {
            desc_cap = (uint16_t)(ECBS__MAX_PAYLOAD_SIZE - 2);
        }
        va_list args = {0};
        va_start(args, fmt);
        int const printed = vsnprintf((char*)&payload[1], desc_cap + 1, fmt, args);
        va_end(args);
        ASSERTf(0 <= printed, ER_1, "vsnprintf() failed: %i", printed);
        uint16_t const desc_len = (printed > desc_cap) ? desc_cap : (uint16_t)printed;
        payload_size = 1 + desc_len + 1;
    }

    ecbs->pending_ep = ECBS__NO_PENDING_EP;
    TRY(_send_packet(ecbs, ECBS__PD_TYPE_APP_ERR, ecbs->last_tid, ecbs->last_data_id, NULL, payload_size));
    ecbs->answer_size = ecbs->send_total;

 finally:

    return rc;
}

int ecbs__send_async(struct Ecbs* const ecbs, EcbsDataId const data_id, uint8_t const* const data,
    uint16_t const data_size) {
    int rc = 0;

    ASSERT(ECBS_STATE__RECEIVE == ecbs->state, ER_BUSY);
    ASSERT((NULL != data) || (0 == data_size), ER_INVAL);
    ASSERTf(ECBS__MAX_PAYLOAD_SIZE >= data_size, ER_ENT_TOO_BIG, "Data too big: %u", data_size);

    TRY(_send_packet(ecbs, ECBS__PD_TYPE_PUB_DATA, 0, data_id, data, data_size));
    ecbs->answer_size = 0;

 finally:

    return rc;
}

int ecbs__process(struct Ecbs* const ecbs) {
    uint64_t const now = ecbs->get_time_ms();

    switch (ecbs->state) {
    case ECBS_STATE__RECEIVE:
    case ECBS_STATE__WAIT_ANSWER:
        return _receive(ecbs, now);
    case ECBS_STATE__SEND:
        return _send_step(ecbs);
    default:
        LOG_ERRf("Unknown state: %i", (int)ecbs->state);
        return ER_PROTO_INTERNAL;
    }
}
