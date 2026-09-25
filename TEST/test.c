#include <ecbs.h>
#include <framer7b.h>
#include <crc32.h>
#include <byteorder.h>
#include <safe_c.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define CHECK(cond)                                                                     \
    do {                                                                                 \
        if (!(cond)) {                                                                   \
            fprintf(stderr, "  CHECK FAILED %s:%i: %s\n", __func__, __LINE__, #cond);   \
            return -1;                                                                   \
        }                                                                                \
    } while (0)

enum {
    TEST__SLAVE_ADDR = 1,
    TEST__OTHER_ADDR = 2,
    TEST__IO_SIZE = 8192,
    TEST__FRAME_BUF_SIZE = FRAMER7B_FRAME_SIZE(ECBS__MAX_PAYLOAD_SIZE + ECBS__MIN_PACKET_SIZE),

    TEST__EP_DATA_ID = 100,
    TEST__EP2_DATA_ID = 200,
    TEST__EP3_DATA_ID = 300,
    TEST__UNKNOWN_DATA_ID = 555,
    TEST__TIMEOUT_MS = 100,

    TEST__PD_POS = 0,
    TEST__ADDR_POS = 1,
    TEST__TID_POS = 2,
    TEST__DATA_ID_POS = 4,
    TEST__PAYLOAD_POS = 6,
    TEST__CRC_SIZE = 4,

    TEST__PD_DIR_REQ = 0x80,
    TEST__PD_TYPE_MASK = 0x0F,
    TEST__PD_TYPE_WRITE = 0x00,
    TEST__PD_TYPE_WRITE_NO_ANSW = 0x01,
    TEST__PD_TYPE_READ = 0x02,
    TEST__PD_TYPE_PUB_DATA = 0x03,
    TEST__PD_TYPE_APP_ERR = 0x0E,
    TEST__PD_TYPE_PROTO_ERR = 0x0F,
};

typedef struct TestAnswer {
    uint8_t pd;
    uint8_t addr;
    uint16_t tid;
    uint16_t data_id;
    uint8_t const* payload;
    uint16_t payload_size;
} TestAnswer;

static struct Ecbs g_ecbs;
static uint64_t g_time_ms;

static uint8_t g_rx[TEST__IO_SIZE];
static uint16_t g_rx_head;
static uint16_t g_rx_tail;

static uint8_t g_tx[TEST__IO_SIZE];
static uint16_t g_tx_len;

static uint8_t g_frame_buf[TEST__FRAME_BUF_SIZE];
static uint8_t g_answer_buf[TEST__FRAME_BUF_SIZE];
static struct Framer7bReceiver g_answer_framer;

static int g_write_accept_max; // 0 - accept all, < 0 - transport busy(accept nothing)
static int g_write_status_mode; // 0 - completed, 1 - proceeds_left times proceeded, 2 - failed
static int g_write_status_proceeds_left;

static int g_read_calls;
static int g_write_calls;
static bool g_write_answer_needed;
static EcbsRequestToken g_last_token;
static EcbsDataId g_last_id;
static uint8_t g_write_payload[ECBS__MAX_PAYLOAD_SIZE];
static uint16_t g_write_payload_size;
static int g_ep_mode; // 0 - defer, 1 - answer inside the callback, 2 - return g_ep_rc
static int g_ep_rc;
static uint8_t g_answer_data[32];
static uint16_t g_answer_data_size;

static void test_print(char const* const str) {
    fputs(str, stdout);
}

static int mock_read(uint8_t* const buf, uint16_t const buf_size) {
    uint16_t n = 0;
    while ((n < buf_size) && (g_rx_tail != g_rx_head)) {
        buf[n] = g_rx[g_rx_tail];
        g_rx_tail = (uint16_t)((g_rx_tail + 1) & (TEST__IO_SIZE - 1));
        n += 1;
    }
    return n;
}

static int mock_write(uint8_t const* const data, uint16_t const ndata) {
    if (0 > g_write_accept_max) {
        return 0; // Transport is busy.
    }

    int accept = (int)ndata;
    if ((0 != g_write_accept_max) && (g_write_accept_max < accept)) {
        accept = g_write_accept_max;
    }
    if (g_tx_len + accept > TEST__IO_SIZE) {
        return -5;
    }
    if (0 < accept) {
        memcpy(&g_tx[g_tx_len], data, (size_t)accept);
    }
    g_tx_len = (uint16_t)(g_tx_len + accept);
    return accept;
}

static enum EcbsWriteStatus mock_get_write_status(void) {
    if (0 == g_write_status_mode) {
        return ECBS_WRITE_STATUS__COMPLETED;
    }
    if (1 == g_write_status_mode) {
        if (0 < g_write_status_proceeds_left) {
            g_write_status_proceeds_left -= 1;
            return ECBS_WRITE_STATUS__PROCEEDED;
        }
        return ECBS_WRITE_STATUS__COMPLETED;
    }
    return ECBS_WRITE_STATUS__FAILED;
}

static uint64_t mock_get_time_ms(void) {
    return g_time_ms;
}

static int mock_read_cb(EcbsDataId const id, EcbsRequestToken const token, void* const user_data) {
    UNUSED(user_data);
    g_read_calls += 1;
    g_last_token = token;
    g_last_id = id;
    if (1 == g_ep_mode) {
        return ecbs__send_read_answer(&g_ecbs, token, g_answer_data, g_answer_data_size);
    }
    return g_ep_rc;
}

static int mock_write_cb(EcbsDataId const id, EcbsRequestToken const token, bool const is_answer_needed,
    uint8_t const* const data, uint16_t const data_size, void* const user_data) {
    UNUSED(user_data);
    g_write_calls += 1;
    g_last_token = token;
    g_last_id = id;
    g_write_answer_needed = is_answer_needed;
    g_write_payload_size = data_size;
    if ((NULL != data) && (0 < data_size)) {
        memcpy(g_write_payload, data, data_size);
    }
    if (is_answer_needed && (1 == g_ep_mode)) {
        return ecbs__send_write_answer(&g_ecbs, token);
    }
    return g_ep_rc;
}

static void reset_mocks(void) {
    g_time_ms = 0;
    g_rx_head = 0;
    g_rx_tail = 0;
    g_tx_len = 0;
    g_write_accept_max = 0;
    g_write_status_mode = 0;
    g_write_status_proceeds_left = 0;
    g_read_calls = 0;
    g_write_calls = 0;
    g_write_answer_needed = false;
    memset(&g_last_token, 0, sizeof(g_last_token));
    g_last_id = 0;
    g_write_payload_size = 0;
    g_ep_mode = 0;
    g_ep_rc = 0;
    g_answer_data_size = 0;
    framer7b_receiver__reset(&g_answer_framer);
    memset(&g_ecbs, 0, sizeof(g_ecbs));
}

static int slave_start(void) {
    return ecbs__init(&g_ecbs, TEST__SLAVE_ADDR, mock_get_time_ms, mock_read, mock_write, mock_get_write_status);
}

static void rx_push_byte(uint8_t const byte) {
    g_rx[g_rx_head] = byte;
    g_rx_head = (uint16_t)((g_rx_head + 1) & (TEST__IO_SIZE - 1));
}

static int queue_packet(uint8_t const pd, uint8_t const addr, uint16_t const tid, uint16_t const data_id,
    uint8_t const* const payload, uint16_t const payload_size) {
    uint16_t const body_size = TEST__PAYLOAD_POS + payload_size;

    g_frame_buf[TEST__PD_POS] = pd;
    g_frame_buf[TEST__ADDR_POS] = addr;
    u16_to_le(&g_frame_buf[TEST__TID_POS], tid);
    u16_to_le(&g_frame_buf[TEST__DATA_ID_POS], data_id);
    if ((NULL != payload) && (0 < payload_size)) {
        memcpy(&g_frame_buf[TEST__PAYLOAD_POS], payload, payload_size);
    }
    u32_to_le(&g_frame_buf[body_size], crc32__ieee(g_frame_buf, body_size));

    int const frame_size = framer7b__encode_in_place(g_frame_buf, body_size + TEST__CRC_SIZE, sizeof(g_frame_buf));
    if (0 >= frame_size) {
        return ER_1;
    }
    for (int i = 0; i < frame_size; i++) {
        rx_push_byte(g_frame_buf[i]);
    }
    return 0;
}

static int process_all(void) {
    int rc = 0;
    for (int i = 0; i < 16; i++) {
        rc = ecbs__process(&g_ecbs);
        if (0 != rc) {
            return rc;
        }
    }
    return rc;
}

static int queue_read(uint16_t const tid) {
    return queue_packet(TEST__PD_DIR_REQ | TEST__PD_TYPE_READ, TEST__SLAVE_ADDR, tid, TEST__EP_DATA_ID, NULL, 0);
}

/** @brief Take the first decoded frame from the slave tx, verify it.
 *
 * @return 0 - taken, < 0 - no answer or invalid answer.
 */
static int take_answer(TestAnswer* const ans) {
    for (uint16_t i = 0; i < g_tx_len; i++) {
        int const r = framer7b_receiver__push(&g_answer_framer, g_tx[i]);
        if (0 < r) {
            g_tx_len = 0;
            uint8_t* const pkt = framer7b_receiver__buf(&g_answer_framer);
            uint16_t const size = (uint16_t)r;
            if ((TEST__PAYLOAD_POS + TEST__CRC_SIZE) > size) {
                return -1;
            }
            uint16_t const body_size = size - TEST__CRC_SIZE;
            uint32_t const crc_recv = u32_from_le(&pkt[body_size]);
            uint32_t const crc_calc = crc32__ieee(pkt, body_size);
            if (crc_recv != crc_calc) {
                return -2;
            }
            ans->pd = pkt[TEST__PD_POS];
            ans->addr = pkt[TEST__ADDR_POS];
            ans->tid = u16_from_le(&pkt[TEST__TID_POS]);
            ans->data_id = u16_from_le(&pkt[TEST__DATA_ID_POS]);
            ans->payload = &pkt[TEST__PAYLOAD_POS];
            ans->payload_size = body_size - TEST__PAYLOAD_POS;
            return 0;
        }
    }
    g_tx_len = 0;
    return -3;
}

static int register_default_endpoint(void) {
    return ecbs__register_endpoint(&g_ecbs, TEST__EP_DATA_ID, TEST__TIMEOUT_MS, NULL, mock_read_cb, mock_write_cb);
}

// --------------------------------------------------------------------------- tests

static int test_init_and_register(void) {
    CHECK(0 == slave_start());
    CHECK(ECBS_STATE__RECEIVE == g_ecbs.state);
    CHECK(ECBS__NO_PENDING_EP == g_ecbs.pending_ep);

    CHECK(ER_INVAL == ecbs__register_endpoint(&g_ecbs, TEST__EP_DATA_ID, 0, NULL, mock_read_cb, mock_write_cb));
    CHECK(ER_INVAL == ecbs__register_endpoint(&g_ecbs, TEST__EP_DATA_ID, TEST__TIMEOUT_MS, NULL, NULL, NULL));

    CHECK(0 == register_default_endpoint());
    CHECK(ER_ALREADY == ecbs__register_endpoint(&g_ecbs, TEST__EP_DATA_ID, TEST__TIMEOUT_MS, NULL, mock_read_cb,
        mock_write_cb));

    for (int i = 0; i < (ECBS__MAX_ENDPOINTS - 1); i++) {
        CHECK(0 == ecbs__register_endpoint(&g_ecbs, (EcbsDataId)(1000 + i), TEST__TIMEOUT_MS, NULL, mock_read_cb,
            mock_write_cb));
    }
    CHECK(ER_NO_MEM == ecbs__register_endpoint(&g_ecbs, 5000, TEST__TIMEOUT_MS, NULL, mock_read_cb, mock_write_cb));

    uint64_t tl = 7;
    CHECK(0 == ecbs__get_tl_master_activity(&g_ecbs, &tl));
    CHECK(0 == tl);

    return 0;
}

static int test_read_answer_inside_callback(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    g_ep_mode = 1;
    uint8_t const data[2] = {0xAB, 0xCD};
    memcpy(g_answer_data, data, sizeof(data));
    g_answer_data_size = sizeof(data);

    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());

    CHECK(1 == g_read_calls);
    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_READ == ans.pd);
    CHECK(TEST__SLAVE_ADDR == ans.addr);
    CHECK(1 == ans.tid);
    CHECK(TEST__EP_DATA_ID == ans.data_id);
    CHECK(2 == ans.payload_size);
    CHECK(0 == memcmp(ans.payload, data, sizeof(data)));
    CHECK(ECBS_STATE__RECEIVE == g_ecbs.state);

    return 0;
}

static int test_read_deferred_answer(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);
    CHECK(0 == g_tx_len);
    CHECK(1 == g_read_calls);

    uint8_t const data[3] = {1, 2, 3};
    CHECK(0 == ecbs__send_read_answer(&g_ecbs, g_last_token, data, sizeof(data)));
    CHECK(0 == process_all());

    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_READ == ans.pd);
    CHECK(1 == ans.tid);
    CHECK(3 == ans.payload_size);
    CHECK(0 == memcmp(ans.payload, data, sizeof(data)));

    return 0;
}

static int test_read_deferred_timeout(void) {
    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);

    g_time_ms = TEST__TIMEOUT_MS;
    CHECK(0 == process_all());
    CHECK(ECBS_STATE__RECEIVE == g_ecbs.state);
    CHECK(ECBS__NO_PENDING_EP == g_ecbs.pending_ep);
    CHECK(0 == g_tx_len);

    uint8_t const data[1] = {0};
    CHECK(ER_TIMEDOUT == ecbs__send_read_answer(&g_ecbs, g_last_token, data, sizeof(data)));

    return 0;
}

static int test_read_retry_after_timeout_reprocessed(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    g_time_ms = TEST__TIMEOUT_MS;
    CHECK(0 == process_all());
    CHECK(1 == g_read_calls);

    // Retry of the same request, no stored answer - re-process.
    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(2 == g_read_calls);
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);

    uint8_t const data[1] = {0x55};
    CHECK(0 == ecbs__send_read_answer(&g_ecbs, g_last_token, data, sizeof(data)));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_READ == ans.pd);
    CHECK(1 == ans.tid);
    CHECK(1 == ans.payload_size);
    CHECK(0x55 == ans.payload[0]);

    return 0;
}

static int test_read_auto_app_err(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    g_ep_mode = 2;
    g_ep_rc = -7;

    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());

    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_APP_ERR == ans.pd);
    CHECK(1 == ans.tid);
    CHECK(TEST__EP_DATA_ID == ans.data_id);
    CHECK(1 == ans.payload_size);
    CHECK(7 == ans.payload[0]);
    CHECK(ECBS_STATE__RECEIVE == g_ecbs.state);

    return 0;
}

static int test_write_answer(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    uint8_t const data[2] = {1, 2};
    CHECK(0 == queue_packet(TEST__PD_DIR_REQ | TEST__PD_TYPE_WRITE, TEST__SLAVE_ADDR, 1, TEST__EP_DATA_ID, data,
        sizeof(data)));
    CHECK(0 == process_all());

    CHECK(1 == g_write_calls);
    CHECK(TEST__EP_DATA_ID == g_last_id);
    CHECK(true == g_write_answer_needed);
    CHECK(2 == g_write_payload_size);
    CHECK(0 == memcmp(g_write_payload, data, sizeof(data)));
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);

    CHECK(0 == ecbs__send_write_answer(&g_ecbs, g_last_token));
    CHECK(0 == process_all());

    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_WRITE == ans.pd);
    CHECK(1 == ans.tid);
    CHECK(TEST__EP_DATA_ID == ans.data_id);
    CHECK(0 == ans.payload_size);

    return 0;
}

static int test_write_no_answer_unicast(void) {
    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    uint8_t const data[2] = {9, 8};
    CHECK(0 == queue_packet(TEST__PD_DIR_REQ | TEST__PD_TYPE_WRITE_NO_ANSW, TEST__SLAVE_ADDR, 0, TEST__EP_DATA_ID,
        data, sizeof(data)));
    CHECK(0 == process_all());

    CHECK(1 == g_write_calls);
    CHECK(false == g_write_answer_needed);
    CHECK(2 == g_write_payload_size);
    CHECK(0 == memcmp(g_write_payload, data, sizeof(data)));
    CHECK(0 == g_tx_len);
    CHECK(ECBS_STATE__RECEIVE == g_ecbs.state);

    // WRITE_NO_ANSW creates no transaction, the answer is rejected.
    CHECK(ER_TIMEDOUT == ecbs__send_write_answer(&g_ecbs, g_last_token));

    return 0;
}

static int test_broadcast(void) {
    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    uint8_t const data[1] = {5};
    CHECK(0 == queue_packet(TEST__PD_DIR_REQ | TEST__PD_TYPE_WRITE_NO_ANSW, ECBS__BROADCAST_ADDR, 0, TEST__EP_DATA_ID,
        data, sizeof(data)));
    CHECK(0 == process_all());

    CHECK(1 == g_write_calls);
    CHECK(false == g_write_answer_needed);
    CHECK(0 == g_tx_len);

    // READ to broadcast is dropped.
    CHECK(0 == queue_packet(TEST__PD_DIR_REQ | TEST__PD_TYPE_READ, ECBS__BROADCAST_ADDR, 1, TEST__EP_DATA_ID, NULL, 0));
    CHECK(0 == process_all());
    CHECK(0 == g_read_calls);
    CHECK(0 == g_tx_len);
    CHECK(ECBS_STATE__RECEIVE == g_ecbs.state);

    return 0;
}

static int test_foreign_addr_and_master_activity(void) {
    uint64_t tl = 0;

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    g_time_ms = 50;
    CHECK(0 == queue_packet(TEST__PD_DIR_REQ | TEST__PD_TYPE_READ, TEST__OTHER_ADDR, 1, TEST__EP_DATA_ID, NULL, 0));
    CHECK(0 == process_all());
    CHECK(0 == g_read_calls);
    CHECK(0 == g_tx_len);

    // Foreign addr, but valid request crc - is an approved master activity.
    CHECK(0 == ecbs__get_tl_master_activity(&g_ecbs, &tl));
    CHECK(50 == tl);

    // Answer direction packet is not a master activity.
    g_time_ms = 100;
    CHECK(0 == queue_packet(TEST__PD_TYPE_READ, TEST__SLAVE_ADDR, 1, TEST__EP_DATA_ID, NULL, 0));
    CHECK(0 == process_all());
    CHECK(0 == ecbs__get_tl_master_activity(&g_ecbs, &tl));
    CHECK(50 == tl);

    // Bad crc is not an approved activity.
    g_time_ms = 150;
    uint16_t const head_before = g_rx_head;
    CHECK(0 == queue_read(1));
    g_rx[(uint16_t)((head_before + 1) & (TEST__IO_SIZE - 1))] ^= 0x01; // Corrupt the first encoded byte.
    CHECK(0 == process_all());
    CHECK(0 == ecbs__get_tl_master_activity(&g_ecbs, &tl));
    CHECK(50 == tl);
    CHECK(0 == g_read_calls);

    // Valid request for us - activity updated, endpoint called.
    g_time_ms = 200;
    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(0 == ecbs__get_tl_master_activity(&g_ecbs, &tl));
    CHECK(200 == tl);
    CHECK(1 == g_read_calls);

    return 0;
}

static int test_proto_err_cases(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    // READ with non-zero transaction_id and non-empty payload.
    uint8_t const data[1] = {1};
    CHECK(0 == queue_packet(TEST__PD_DIR_REQ | TEST__PD_TYPE_READ, TEST__SLAVE_ADDR, 1, TEST__EP_DATA_ID, data,
        sizeof(data)));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_PROTO_ERR == ans.pd);
    CHECK(1 == ans.tid);
    CHECK(TEST__EP_DATA_ID == ans.data_id);
    CHECK(1 == ans.payload_size);
    CHECK(ECBS_PROTO_ERR__INVALID_PAYLOAD_SIZE == ans.payload[0]);
    CHECK(0 == g_read_calls);

    // READ with zero transaction_id.
    CHECK(0 == queue_read(0));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_PROTO_ERR == ans.pd);
    CHECK(0 == ans.tid);
    CHECK(ECBS_PROTO_ERR__INVALID_TRANSACTION_ID == ans.payload[0]);
    CHECK(0 == g_read_calls);

    return 0;
}

static int test_side_err_while_pending(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    // Pending deferred READ request.
    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);
    CHECK(1 == g_read_calls);

    // Protocol invalid request while pending: answered, pending is not touched.
    uint8_t const data[1] = {1};
    CHECK(0 == queue_packet(TEST__PD_DIR_REQ | TEST__PD_TYPE_READ, TEST__SLAVE_ADDR, 9, TEST__EP_DATA_ID, data,
        sizeof(data)));
    CHECK(0 == process_all());

    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_PROTO_ERR == ans.pd);
    CHECK(9 == ans.tid);
    CHECK(ECBS_PROTO_ERR__INVALID_PAYLOAD_SIZE == ans.payload[0]);

    // The pending request is still alive after the side error answer send.
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);
    CHECK(1 == g_read_calls);

    uint8_t const answer[2] = {0x0A, 0x0B};
    CHECK(0 == ecbs__send_read_answer(&g_ecbs, g_last_token, answer, sizeof(answer)));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_READ == ans.pd);
    CHECK(1 == ans.tid);
    CHECK(2 == ans.payload_size);

    return 0;
}

static int test_app_err_no_data_id_and_no_operation(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    CHECK(0 == queue_packet(TEST__PD_DIR_REQ | TEST__PD_TYPE_READ, TEST__SLAVE_ADDR, 1, TEST__UNKNOWN_DATA_ID, NULL,
        0));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_APP_ERR == ans.pd);
    CHECK(TEST__UNKNOWN_DATA_ID == ans.data_id);
    CHECK(1 == ans.payload_size);
    CHECK(ECBS_APP_ERR__NO_DATA_ID == ans.payload[0]);

    // Registered endpoint with write only - read is not supported.
    CHECK(0 == ecbs__register_endpoint(&g_ecbs, TEST__EP2_DATA_ID, TEST__TIMEOUT_MS, NULL, NULL, mock_write_cb));
    CHECK(0 == queue_packet(TEST__PD_DIR_REQ | TEST__PD_TYPE_READ, TEST__SLAVE_ADDR, 2, TEST__EP2_DATA_ID, NULL, 0));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_APP_ERR == ans.pd);
    CHECK(1 == ans.payload_size);
    CHECK(ECBS_APP_ERR__NO_OPERATION == ans.payload[0]);
    CHECK(0 == g_read_calls);

    // Write to read only endpoint.
    CHECK(0 == ecbs__register_endpoint(&g_ecbs, TEST__EP3_DATA_ID, TEST__TIMEOUT_MS, NULL, mock_read_cb, NULL));
    CHECK(0 == queue_packet(TEST__PD_DIR_REQ | TEST__PD_TYPE_WRITE, TEST__SLAVE_ADDR, 3, TEST__EP3_DATA_ID, NULL, 0));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_APP_ERR == ans.pd);
    CHECK(1 == ans.payload_size);
    CHECK(ECBS_APP_ERR__NO_OPERATION == ans.payload[0]);
    CHECK(0 == g_write_calls);

    return 0;
}

static int test_dedup_resend(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    g_ep_mode = 1;
    uint8_t const data[1] = {0x11};
    memcpy(g_answer_data, data, sizeof(data));
    g_answer_data_size = sizeof(data);

    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    uint8_t ans1_payload[32] = {0};
    memcpy((uint8_t*)ans1_payload, ans.payload, ans.payload_size);
    uint16_t const ans1_payload_size = ans.payload_size;
    uint8_t const ans1_pd = ans.pd;
    CHECK(1 == g_read_calls);

    // Same request again - the stored answer is resent, the endpoint is not called.
    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(ans1_pd == ans.pd);
    CHECK(1 == ans.tid);
    CHECK(TEST__EP_DATA_ID == ans.data_id);
    CHECK(ans1_payload_size == ans.payload_size);
    CHECK(0 == memcmp(ans1_payload, ans.payload, ans1_payload_size));
    CHECK(1 == g_read_calls);

    return 0;
}

static int test_transaction_conflict(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    g_ep_mode = 1;
    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(1 == ans.tid);
    CHECK(1 == g_read_calls);

    // Same transaction_id, but different request fields.
    CHECK(0 == queue_packet(TEST__PD_DIR_REQ | TEST__PD_TYPE_READ, TEST__SLAVE_ADDR, 1, TEST__EP2_DATA_ID, NULL, 0));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_PROTO_ERR == ans.pd);
    CHECK(1 == ans.tid);
    CHECK(TEST__EP2_DATA_ID == ans.data_id);
    CHECK(1 == ans.payload_size);
    CHECK(ECBS_PROTO_ERR__TRANSACTION_CONFLICT == ans.payload[0]);
    CHECK(1 == g_read_calls);
    CHECK(ECBS_STATE__RECEIVE == g_ecbs.state);

    return 0;
}

static int test_new_request_while_pending(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);
    CHECK(1 == g_read_calls);
    EcbsRequestToken const old_token = g_last_token;

    // A new request while pending: the pending is terminated, the new one is processed.
    CHECK(0 == queue_read(2));
    CHECK(0 == process_all());
    CHECK(2 == g_read_calls);
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);

    // The answer for the terminated request is rejected.
    uint8_t const data[1] = {1};
    CHECK(ER_INVAL == ecbs__send_read_answer(&g_ecbs, old_token, data, sizeof(data)));

    // The new request can be answered.
    CHECK(0 == ecbs__send_read_answer(&g_ecbs, g_last_token, data, sizeof(data)));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_READ == ans.pd);
    CHECK(2 == ans.tid);

    return 0;
}

static int test_retry_while_pending(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);
    CHECK(1 == g_read_calls);

    // Retry of the pending request is ignored.
    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(1 == g_read_calls);
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);
    CHECK(0 == g_tx_len);

    uint8_t const data[1] = {2};
    CHECK(0 == ecbs__send_read_answer(&g_ecbs, g_last_token, data, sizeof(data)));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_READ == ans.pd);
    CHECK(1 == ans.tid);

    return 0;
}

static int test_wrong_token_and_oversize(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);

    EcbsRequestToken const wrong_token = {
        .pd = g_last_token.pd,
        .crc32 = g_last_token.crc32 ^ 0xFFFF,
    };
    uint8_t const data[1] = {1};
    CHECK(ER_INVAL == ecbs__send_read_answer(&g_ecbs, wrong_token, data, sizeof(data)));
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);

    static uint8_t const big_data[ECBS__MAX_PAYLOAD_SIZE + 1] = {0};
    CHECK(ER_ENT_TOO_BIG == ecbs__send_read_answer(&g_ecbs, g_last_token, big_data, sizeof(big_data)));
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);

    // WRITE token cannot be answered by the read answer function.
    EcbsRequestToken const write_token = {
        .pd = g_last_token.pd ^ TEST__PD_TYPE_READ,
        .crc32 = g_last_token.crc32,
    };
    CHECK(ER_INVAL == ecbs__send_read_answer(&g_ecbs, write_token, data, sizeof(data)));

    CHECK(0 == ecbs__send_read_answer(&g_ecbs, g_last_token, data, sizeof(data)));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(1 == ans.tid);

    return 0;
}

static int test_app_error_answer_fmt(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);

    CHECK(0 == ecbs__send_app_error_answer(&g_ecbs, g_last_token, 0x42, "err %i", 7));
    CHECK(0 == process_all());

    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_APP_ERR == ans.pd);
    CHECK(1 == ans.tid);
    CHECK(TEST__EP_DATA_ID == ans.data_id);
    CHECK(7 == ans.payload_size); // error_code + "err 7" + NULL
    CHECK(0x42 == ans.payload[0]);
    CHECK(0 == memcmp(&ans.payload[1], "err 7", 5));
    CHECK(0 == ans.payload[6]);

    return 0;
}

static int test_announce(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == ecbs__announce(&g_ecbs));
    CHECK(ECBS_STATE__SEND == g_ecbs.state);
    CHECK(0 == process_all());

    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_WRITE == ans.pd); // DIR bit is not set - answer direction.
    CHECK(TEST__SLAVE_ADDR == ans.addr);
    CHECK(0 == ans.tid);
    CHECK(65280 == ans.data_id);
    CHECK(0 == ans.payload_size);
    CHECK(ECBS_STATE__RECEIVE == g_ecbs.state);

    // Announce while a transaction is in progress is rejected.
    CHECK(0 == register_default_endpoint());
    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);
    CHECK(ER_BUSY == ecbs__announce(&g_ecbs));

    return 0;
}

static int test_send_async(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());

    uint8_t const data[4] = {1, 2, 3, 4};
    CHECK(0 == ecbs__send_async(&g_ecbs, TEST__EP_DATA_ID, data, sizeof(data)));
    CHECK(0 == process_all());

    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_PUB_DATA == ans.pd);
    CHECK(TEST__SLAVE_ADDR == ans.addr);
    CHECK(0 == ans.tid);
    CHECK(TEST__EP_DATA_ID == ans.data_id);
    CHECK(4 == ans.payload_size);
    CHECK(0 == memcmp(ans.payload, data, sizeof(data)));

    // Send async while pending is rejected.
    CHECK(0 == register_default_endpoint());
    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(ECBS_STATE__WAIT_ANSWER == g_ecbs.state);
    CHECK(ER_BUSY == ecbs__send_async(&g_ecbs, TEST__EP_DATA_ID, data, sizeof(data)));

    return 0;
}

static int test_write_status_flow(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    g_ep_mode = 1;
    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(ECBS_STATE__RECEIVE == g_ecbs.state);
    CHECK(0 == take_answer(&ans));
    CHECK(1 == ans.tid);

    // DMA like transport: write is accepted, but the status is PROCEEDED.
    g_write_status_mode = 1;
    g_write_status_proceeds_left = 2;
    CHECK(0 == queue_read(2));
    CHECK(0 == ecbs__process(&g_ecbs)); // The frame is handled, the answer is queued.
    CHECK(ECBS_STATE__SEND == g_ecbs.state);
    CHECK(0 == ecbs__process(&g_ecbs)); // All bytes accepted, first PROCEEDED.
    CHECK(ECBS_STATE__SEND == g_ecbs.state);
    CHECK(0 == ecbs__process(&g_ecbs)); // Second PROCEEDED.
    CHECK(ECBS_STATE__SEND == g_ecbs.state);
    CHECK(0 == ecbs__process(&g_ecbs)); // COMPLETED.
    CHECK(ECBS_STATE__RECEIVE == g_ecbs.state);

    CHECK(0 == take_answer(&ans));
    CHECK(2 == ans.tid);

    // The slave is ready for the next request.
    CHECK(0 == queue_read(3));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(3 == ans.tid);

    return 0;
}

static int test_partial_write(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    g_ep_mode = 1;
    g_write_accept_max = 3; // The transport accepts 3 bytes per write call.

    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());

    CHECK(0 == take_answer(&ans));
    CHECK(TEST__PD_TYPE_READ == ans.pd);
    CHECK(1 == ans.tid);
    CHECK(ECBS_STATE__RECEIVE == g_ecbs.state);

    return 0;
}

static int test_write_busy_transport(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    g_ep_mode = 1;
    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(ECBS_STATE__RECEIVE == g_ecbs.state);
    CHECK(0 == take_answer(&ans));
    CHECK(1 == ans.tid);

    // The transport accepts nothing now.
    g_write_accept_max = -1;
    CHECK(0 == queue_read(2));
    CHECK(0 == ecbs__process(&g_ecbs)); // The frame is handled, the answer is queued.
    CHECK(ECBS_STATE__SEND == g_ecbs.state);
    CHECK(0 == ecbs__process(&g_ecbs)); // write() returns zero, the send continues later.
    CHECK(ECBS_STATE__SEND == g_ecbs.state);
    CHECK(0 == g_tx_len);

    g_write_accept_max = 0;
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(2 == ans.tid);
    CHECK(ECBS_STATE__RECEIVE == g_ecbs.state);

    return 0;
}

static int test_write_failed_status(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    g_ep_mode = 1;
    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());
    CHECK(ECBS_STATE__RECEIVE == g_ecbs.state);
    CHECK(0 == take_answer(&ans));
    CHECK(1 == ans.tid);
    uint16_t const tx_after_first = g_tx_len;

    g_write_status_mode = 2; // FAILED
    CHECK(0 == queue_read(2));
    CHECK(0 == ecbs__process(&g_ecbs)); // The frame is handled, the answer is queued.
    CHECK(ECBS_STATE__SEND == g_ecbs.state);
    CHECK(ER_IO == ecbs__process(&g_ecbs)); // Bytes accepted, but the status is FAILED.
    CHECK(ECBS_STATE__RECEIVE == g_ecbs.state); // The frame is dropped, the slave is free.
    CHECK(tx_after_first + FRAMER7B_FRAME_SIZE(ECBS__MIN_PACKET_SIZE) == g_tx_len);
    CHECK(0 == take_answer(&ans));
    CHECK(2 == ans.tid); // The failed frame bytes physically reached the transport.

    // The slave recovers and answers the next request.
    g_write_status_mode = 0;
    CHECK(0 == queue_read(3));
    CHECK(0 == process_all());
    CHECK(0 == take_answer(&ans));
    CHECK(3 == ans.tid);

    return 0;
}

static int test_garbage_resync(void) {
    TestAnswer ans = {0};

    CHECK(0 == slave_start());
    CHECK(0 == register_default_endpoint());

    g_ep_mode = 1;
    // Garbage bytes without START marker, then a valid request frame.
    for (int i = 0; i < 10; i++) {
        rx_push_byte((uint8_t)(i * 7 + 1));
    }
    CHECK(0 == queue_read(1));
    CHECK(0 == process_all());

    CHECK(1 == g_read_calls);
    CHECK(0 == take_answer(&ans));
    CHECK(1 == ans.tid);

    return 0;
}

typedef int (*test_fn_t)(void);

static struct {
    char const* name;
    test_fn_t fn;
} const g_tests[] = {
    {"init_and_register", test_init_and_register},
    {"read_answer_inside_callback", test_read_answer_inside_callback},
    {"read_deferred_answer", test_read_deferred_answer},
    {"read_deferred_timeout", test_read_deferred_timeout},
    {"read_retry_after_timeout_reprocessed", test_read_retry_after_timeout_reprocessed},
    {"read_auto_app_err", test_read_auto_app_err},
    {"write_answer", test_write_answer},
    {"write_no_answer_unicast", test_write_no_answer_unicast},
    {"broadcast", test_broadcast},
    {"foreign_addr_and_master_activity", test_foreign_addr_and_master_activity},
    {"proto_err_cases", test_proto_err_cases},
    {"side_err_while_pending", test_side_err_while_pending},
    {"app_err_no_data_id_and_no_operation", test_app_err_no_data_id_and_no_operation},
    {"dedup_resend", test_dedup_resend},
    {"transaction_conflict", test_transaction_conflict},
    {"new_request_while_pending", test_new_request_while_pending},
    {"retry_while_pending", test_retry_while_pending},
    {"wrong_token_and_oversize", test_wrong_token_and_oversize},
    {"app_error_answer_fmt", test_app_error_answer_fmt},
    {"announce", test_announce},
    {"send_async", test_send_async},
    {"write_status_flow", test_write_status_flow},
    {"partial_write", test_partial_write},
    {"write_busy_transport", test_write_busy_transport},
    {"write_failed_status", test_write_failed_status},
    {"garbage_resync", test_garbage_resync},
};

int main(void) {
    safe_c__init(test_print);
    framer7b_receiver__init(&g_answer_framer, g_answer_buf, sizeof(g_answer_buf));

    int failed = 0;
    for (uint32_t i = 0; i < (sizeof(g_tests) / sizeof(g_tests[0])); i++) {
        reset_mocks();
        printf("TEST %s ... ", g_tests[i].name);
        fflush(stdout);
        int const rc = g_tests[i].fn();
        if (0 == rc) {
            printf("PASS\n");
        }
        else {
            printf("FAIL\n");
            failed += 1;
        }
    }

    printf("%u tests, %u failed\n", (unsigned)(sizeof(g_tests) / sizeof(g_tests[0])), (unsigned)failed);

    return 0 != failed ? 1 : 0;
}
