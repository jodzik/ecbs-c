#include "ecb-slave.h"
#include "framer7b.h"
#include "../crc/crc32.h"
#include "../raiden/raiden.h"
#include "../serdes/serdes.h"
#include "../safe-c/safe_c.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>


#define IS_TIME_EXPIRED(tle, period) (ecbs->get_time_ms() - tle >= period || ecbs->get_time_ms() < tle)
#define IS_TIME_EXPIRED_EX(tle, period, now) (now - tle >= period || now < tle)


enum {
    ECBS__ENC_FILLER = 0x5A,
    ECBS__PD_TYPE_MASK = 0b1111,
    ECBS__PD_DIR_MASK = 0b10000,
    ECBS__PD_DIR_IS_REQ = ECBS__PD_DIR_MASK,
    ECBS__PD_DIR_IS_ANSW = 0x00,
    ECBS__PD_IS_ENC_MASK = 0b100000,
    ECBS__PD_TYPE_WRITE = 0b0000,
    ECBS__PD_TYPE_WRITE_NO_ANSW = 0b0010,
    ECBS__PD_TYPE_READ = 0b0001,
    ECBS__PD_TYPE_STREAM_OPEN = 0b0011,
    ECBS__PD_TYPE_STREAM_CLOSE = 0b0100,
    ECBS__PD_TYPE_STREAM_DATA = 0b0101,
    ECBS__PD_TYPE_ENC_OPEN = 0b0110,
    ECBS__PD_TYPE_WRITE_AUTH_REQ = 0b0111,
    ECBS__PD_TYPE_WRITE_WITH_AUTH = 0b1000,
    ECBS__PD_TYPE_ERR = 0b1111,
};

enum {
    // ADDR(1) + PD(1) + SIGNAL(2) + NFILL(1) + SEQ(1)
    PACKET_ADDR_INDEX = 0,
    PACKET_PD_INDEX = 1,
    PACKET_SIGNAL_INDEX = 2,
    PACKET_NFILL_INDEX = 4,
    PACKET_SEQ_INDEX = 5,
    PACKET_DATA_POS = 6,

    NO_SIGNAL = -1,
};

typedef struct Packet {
    uint8_t addr;
    uint8_t pd;
    uint16_t signal;
    uint8_t nfill;
    uint8_t seq;
    uint8_t* data;
    uint16_t ndata;
} Packet;


inline static bool is_broadcast_addr(uint8_t const addr) {
    return addr == ECBS__BROADCAST_ADDR;
}

inline static bool is_need_handle_addr(struct Ecbs const* const ecbs, uint8_t const addr) {
    return addr == ecbs->addr || is_broadcast_addr(addr);
}

static EcbsSig* find_sig(Ecbs* ecbs, int sig) {
    for (uint16_t i = 0; i < ECBS__MAX_SIG; i++) {
        if (ecbs->sig[i].sig == sig) {
            return &ecbs->sig[i];
        }
    }

    return NULL;
}

static int find_sig_index(Ecbs* ecbs, int sig) {
    for (uint16_t i = 0; i < ECBS__MAX_SIG; i++) {
        if (ecbs->sig[i].sig == sig) {
            return i;
        }
    }

    return -1;
}


/// @brief Make packet in buf - insert service info, encrypt if needed
/// @param ndata - size of optionally already written data to #PACKET_DATA_POS
static int make_packet(
    struct Ecbs* const ecbs,
    bool const is_enc,
    uint8_t const pd_type,
    uint16_t const signal,
    uint8_t const seq,
    uint16_t const ndata,
    uint16_t* const packet_size)
{
    uint8_t* const buf = framer7b__get_packet_buf_to_make(&ecbs->framer);
    buf[0] = ecbs->addr;
    buf[1] = pd_type | ECBS__PD_DIR_IS_ANSW | (is_enc ? ECBS__PD_IS_ENC_MASK : 0x00);
    u16_to_be(&buf[2], signal);
    uint8_t nfill = 0;
    if (is_enc) {
        nfill = 8 - (ndata % 8);
        if (nfill == 8) {
            nfill = 0;
        }
        memset(&buf[ndata + PACKET_DATA_POS], ECBS__ENC_FILLER, nfill);
        TRY(raiden_encode_buf(ecbs->session_key, &buf[PACKET_DATA_POS], ndata + nfill));
    }
    buf[4] = nfill;
    buf[5] = seq;
    uint16_t const crc_pos = PACKET_DATA_POS + ndata + nfill;
    u32_to_be(&buf[crc_pos], crc32(buf, crc_pos));
    *packet_size = ndata + nfill + ECBS__MIN_PACKET_SIZE;
    return 0;
}

/// @brief Encode packet to 7B frame.
/// @param ecbs self
/// @param ndata count of already inserted to 'buf_to_make' buffer.
static void encode_packet_and_send_as_frame(struct Ecbs* const ecbs, uint16_t ndata) {
#if ECBS_DEBUG_EN
    uint8_t const* const packet = framer7b__get_packet_buf_to_make(&ecbs->framer);
    ECBS_DBG_PRINTF("Send packet: addr=%u pd=%02X sig=%u seq=%u ndata=%u.", packet[PACKET_ADDR_INDEX],
        packet[PACKET_PD_INDEX], u16_from_be(&packet[PACKET_SIGNAL_INDEX]), packet[PACKET_SEQ_INDEX], ndata);
#endif

    if (ECBS_STATE__SEND == ecbs->state) {
        WRN_LOG("Send packet initiated while a previous packet is still not sended.");
    }
    ecbs->nsend = (uint16_t)framer7b__make(&ecbs->framer, ndata);
    ecbs->ptr = 0;
    ecbs->state = ECBS_STATE__SEND;
    ecbs->is_buffer_sending = false;
}

static int send_err(
    struct Ecbs* const ecbs,
    uint16_t const signal,
    bool const is_enc,
    uint8_t const seq,
    enum EcbsErr const err,
    int app_err)
{
    uint16_t packet_size = 0;
    uint8_t* const buf = framer7b__get_packet_buf_to_make(&ecbs->framer);
    buf[PACKET_DATA_POS] = (uint8_t)err;
    if (app_err < 0) {
        app_err = -app_err;
    }
    u32_to_be(&buf[PACKET_DATA_POS + 1], (uint32_t)app_err);
    TRY(make_packet(ecbs, is_enc, ECBS__PD_TYPE_ERR, signal,  seq,
        1 + sizeof(uint32_t) + ecbs->err_description_size, &packet_size));
    encode_packet_and_send_as_frame(ecbs, packet_size);

    return 0;
}

static int send_stream_data(struct Ecbs* const ecbs) {
    ASSERT(NO_SIGNAL != ecbs->stream_sig, ER_NOT_PERM);

    struct EcbsSig* const signal = &ecbs->sig[ecbs->stream_sig];
    bool const is_enc_needed = ECBS_PROTECT_LEVEL__NO != signal->protect_level;
    uint8_t* const buf = framer7b__get_packet_buf_to_make(&ecbs->framer);
    int const rc = signal->read(signal->sig, &buf[PACKET_DATA_POS]);
    if (rc >= 0) {
        uint16_t packet_size = 0;
        ASSERTf(rc <= ECBS__MAX_DATA_SIZE, ER_INVAL,
            "Fail to send stream data for %i: read data too big - %i", signal->sig, rc);
        TRY(make_packet(ecbs, is_enc_needed, ECBS__PD_TYPE_STREAM_DATA, (uint16_t)signal->sig,
            0, (uint16_t)rc, &packet_size));
        encode_packet_and_send_as_frame(ecbs, packet_size);
        signal->tl_stream_pub_ms = ecbs->get_time_ms();
    } else {
        ECBS_DBG_PRINTF("Fail to send stream data for %i: fail to signal->read(): %i", signal->sig, rc);
        return rc;
    }

    return 0;
}

static int handle_read_request(struct Ecbs* const ecbs, struct Packet const* packet) {
    bool const is_enc = packet->pd & ECBS__PD_IS_ENC_MASK;
    struct EcbsSig* const sig = find_sig(ecbs, packet->signal);
    
    ASSERTm(!is_broadcast_addr(packet->addr), ER_NOT_PERM, "Fail to handle read request: broadcast addr not allowed");

    if (NULL == sig) {
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__NO_SIG, 0);
        return 0;
    }
    if (NULL == sig->read) {
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__NO_OPERATION, 0);
        return 0;
    }
    bool const is_enc_needed = ECBS_PROTECT_LEVEL__NO != sig->protect_level;
    if (is_enc_needed && !is_enc) {
        ECBS_DBG_PRINT("Cancel handle packet: enc needed");
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__ENC_REQUIRED, 0);
        return 0;
    }
    uint8_t* const buf = framer7b__get_packet_buf_to_make(&ecbs->framer);
    int const rc = sig->read(sig->sig, &buf[PACKET_DATA_POS]);
    if (rc >= 0) {
        uint16_t packet_size = 0;
        ASSERTf(rc <= ECBS__MAX_DATA_SIZE, ER_INVAL, "Fail to handle read request: read data too big - %i", rc);
        make_packet(ecbs, is_enc, ECBS__PD_TYPE_READ, (uint16_t)sig->sig, packet->seq, (uint16_t)rc, &packet_size);
        encode_packet_and_send_as_frame(ecbs, packet_size);
    } else {
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__APP, rc);
        ECBS_DBG_PRINTF("Fail to read signal: user error: %i", rc);
    }

    return 0;
}

static int handle_write_request(struct Ecbs* const ecbs, struct Packet const* packet) {
    bool const is_enc = packet->pd & ECBS__PD_IS_ENC_MASK;
    struct EcbsSig* const sig = find_sig(ecbs, packet->signal);
    
    ASSERTm(!is_broadcast_addr(packet->addr), ER_NOT_PERM, "Fail to handle write request: broadcast addr not allowed");

    if (NULL == sig) {
        send_err(ecbs, packet->signal, packet->seq, is_enc, ECBS_ERR__NO_SIG, 0);
        return 0;
    }
    if (NULL == sig->write) {
        send_err(ecbs, packet->signal, packet->seq, is_enc, ECBS_ERR__NO_OPERATION, 0);
        return 0;
    }
    bool const is_enc_needed = ECBS_PROTECT_LEVEL__NO != sig->protect_level;
    if (is_enc_needed && !is_enc) {
        ECBS_DBG_PRINT("Cancel handle packet: enc needed");
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__ENC_REQUIRED, 0);
        return 0;
    }
    if (ECBS_PROTECT_LEVEL__ENC_AND_WRITE_AUTH == sig->protect_level) {
        ECBS_DBG_PRINT("Cancel handle packet: auth write only");
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__AUTH_REQUIRED, 0);
        return 0;
    }

    int const rc = sig->write(sig->sig, packet->data, packet->ndata);
    if (0 == rc) {
        uint16_t packet_size = 0;
        TRY(make_packet(ecbs, is_enc, ECBS__PD_TYPE_WRITE, (uint16_t)sig->sig, packet->seq, 0, &packet_size));
        encode_packet_and_send_as_frame(ecbs, packet_size);
    } else {
        ECBS_DBG_PRINTF("Fail to write signal %u: user error: %i", packet->signal, rc);
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__APP, rc);
    }

    return 0;
}

static int handle_write_no_answ_request(struct Ecbs* const ecbs, struct Packet const* packet) {
    int rc = 0;
    bool const is_enc = packet->pd & ECBS__PD_IS_ENC_MASK;
    struct EcbsSig* const sig = find_sig(ecbs, packet->signal);
    if (NULL == sig) {
        return 0;
    }
    if (NULL == sig->write) {
        return 0;
    }
    bool const is_enc_needed = ECBS_PROTECT_LEVEL__NO != sig->protect_level;
    if (is_enc_needed && !is_enc) {
        ECBS_DBG_PRINT("Cancel handle write_no_answ request: enc needed");
        return 0;
    }
    if (ECBS_PROTECT_LEVEL__ENC_AND_WRITE_AUTH == sig->protect_level) {
        ECBS_DBG_PRINT("Cancel handle write_no_answ request: auth write only");
        return 0;
    }

    rc = sig->write(sig->sig, packet->data, packet->ndata);
    if (rc) {
        ECBS_DBG_PRINTF("Fail to write signal %u: user error: %i", packet->signal, rc);
    }

    return 0;
}

static int handle_write_auth_request(struct Ecbs* const ecbs, struct Packet const* packet) {
    bool const is_enc = packet->pd & ECBS__PD_IS_ENC_MASK;
    struct EcbsSig* const sig = find_sig(ecbs, packet->signal);
    uint16_t packet_size = 0;
    
    ASSERTm(!is_broadcast_addr(packet->addr), ER_NOT_PERM,
        "Fail to handle write_auth request: broadcast addr not allowed");

    if (NULL == sig) {
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__NO_SIG, 0);
        return 0;
    }
    if (NULL == sig->write) {
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__NO_OPERATION, 0);
        return 0;
    }
    if (is_enc) {
        ECBS_DBG_PRINT("Cancel handle write_auth request: enc not allowed");
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__INTERNAL, ECBS_INTERNAL_ERR__ENC_NOT_ALLOWED);
        return 0;
    }
    if (!ecbs->is_enc_session) {
        ECBS_DBG_PRINT("Cancel handle write_auth request: no enc session");
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__NO_ENC_SESSION, 0);
        return 0;
    }
    uint8_t* const buf = framer7b__get_packet_buf_to_make(&ecbs->framer);
    u32_to_be(ecbs->write_auth_rand_key, ecbs->get_rand());
    u32_to_be(&ecbs->write_auth_rand_key[4], ecbs->get_rand());
    memcpy(ecbs->write_auth_rand_key, &buf[PACKET_DATA_POS], sizeof(uint64_t));
    TRY(make_packet(ecbs, false, ECBS__PD_TYPE_WRITE_AUTH_REQ, (uint16_t)sig->sig,
        packet->seq, sizeof(uint64_t), &packet_size));
    encode_packet_and_send_as_frame(ecbs, packet_size);
    
    return 0;
}

static int handle_write_with_auth_request(struct Ecbs* const ecbs, struct Packet const* packet) {
    bool const is_enc = packet->pd & ECBS__PD_IS_ENC_MASK;
    struct EcbsSig* const sig = find_sig(ecbs, packet->signal);

    ASSERTm(!is_broadcast_addr(packet->addr), ER_NOT_PERM, "Fail to handle write request: broadcast addr not allowed");

    if (NULL == sig) {
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__NO_SIG, 0);
        return 0;
    }
    if (NULL == sig->write) {
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__NO_OPERATION, 0);
        return 0;
    }
    if (!is_enc) {
        ECBS_DBG_PRINT("Cancel handle write_with_auth request: enc needed");
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__ENC_REQUIRED, 0);
        return 0;
    }
    if (packet->ndata < sizeof(uint64_t)) {
        ERR_LOGf("Cancel handle write_with_auth request: packet not contain sign, ndata=%i", packet->ndata);
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__INTERNAL, ECBS_INTERNAL_ERR__NO_SIGN);
        return ER_INVAL;
    }
    if (0 != memcmp(packet->data, ecbs->write_auth_rand_key, sizeof(uint64_t))) {
        send_err(ecbs, packet->signal, true, packet->seq, ECBS_ERR__INCORRECT_SIGN, 0);
        return 0;
    }
    int const rc = sig->write(sig->sig, &packet->data[sizeof(uint64_t)], packet->ndata - sizeof(uint64_t));
    if (0 == rc) {
        uint16_t packet_size = 0;
        TRY(make_packet(ecbs, true, ECBS__PD_TYPE_WRITE_WITH_AUTH, (uint16_t)sig->sig, packet->seq, 0, &packet_size));
        encode_packet_and_send_as_frame(ecbs, packet_size);
    }
    else {
        ECBS_DBG_PRINTF("Fail to write signal %u: user error: %i", packet->signal, rc);
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__APP, rc);
    }

    return 0;
}

static int handle_stream_open_request(struct Ecbs* const ecbs, struct Packet const* packet) {
    bool const is_enc = packet->pd & ECBS__PD_IS_ENC_MASK;
    struct EcbsSig* const sig = find_sig(ecbs, packet->signal);
    uint16_t packet_size = 0;

    ASSERTm(!is_broadcast_addr(packet->addr), ER_NOT_PERM,
        "Fail to handle stream_open request: broadcast addr not allowed");

    if (NULL == sig) {
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__NO_SIG, 0);
        return 0;
    }
    if (NULL == sig->read || !sig->is_stream_allowed) {
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__NO_OPERATION, 0);
        return 0;
    }
    bool const is_enc_needed = ECBS_PROTECT_LEVEL__NO != sig->protect_level;
    if (is_enc_needed && !is_enc) {
        ECBS_DBG_PRINT("Cancel handle stream_open request: enc needed");
        send_err(ecbs, packet->signal, is_enc, packet->seq, ECBS_ERR__ENC_REQUIRED, 0);
        return 0;
    }

    ecbs->stream_sig = find_sig_index(ecbs, packet->signal);

    TRY(make_packet(ecbs, is_enc, ECBS__PD_TYPE_STREAM_OPEN, (uint16_t)sig->sig, packet->seq, 0, &packet_size));
    encode_packet_and_send_as_frame(ecbs, packet_size);

    return 0;
}

static int handle_stream_close_request(struct Ecbs* const ecbs, struct Packet const* packet) {
    bool const is_enc = packet->pd & ECBS__PD_IS_ENC_MASK;

    ecbs->stream_sig = NO_SIGNAL;

    if (!is_broadcast_addr(packet->addr)) {
        uint16_t packet_size = 0;
        TRY(make_packet(ecbs, is_enc, ECBS__PD_TYPE_STREAM_CLOSE, 0, packet->seq, 0, &packet_size));
        encode_packet_and_send_as_frame(ecbs, packet_size);
    }

    return 0;
}

static int handle_enc_open_request(struct Ecbs* const ecbs, struct Packet const* packet) {
    uint16_t packet_size = 0;

    ASSERTm(!is_broadcast_addr(packet->addr), ER_NOT_PERM,
        "Fail to handle enc_open request: broadcast addr not allowed");

    if (!ecbs->is_enc_init) {
        send_err(ecbs, 0, false, packet->seq, ECBS_ERR__ENC_NOT_SUPPORTED, 0);
        return 0;
    }

    uint8_t* const buf = framer7b__get_packet_buf_to_make(&ecbs->framer);
    srand(ecbs->get_rand());
    for (uint8_t i = 0; i < RAIDEN__KEY_SIZE; i += sizeof(uint16_t)) {
        u16_to_be(&ecbs->session_key[i], (uint16_t)rand());
    }
    TRY(raiden_encode(ecbs->auth_key, ecbs->session_key, &buf[PACKET_DATA_POS], RAIDEN__KEY_SIZE));
    TRY(make_packet(ecbs, false, ECBS__PD_TYPE_ENC_OPEN, 0, 0, RAIDEN__KEY_SIZE, &packet_size));
    encode_packet_and_send_as_frame(ecbs, packet_size);
    ecbs->is_enc_session = true;

    return 0;
}

static int handle_packet(Ecbs* ecbs, size_t ndata) {
    ecbs->err_description_size = 0;

    if (ndata < ECBS__MIN_PACKET_SIZE) {
        ECBS_DBG_PRINTF("Fail to parse packet: ndata(%i) less than minimum packet size %i", ndata, ECBS__MIN_PACKET_SIZE);
        return ER_1;
    }

    uint8_t* const buf = framer7b__get_received_packet_buf(&ecbs->framer);
    uint32_t const crc_calc = crc32(buf, ndata - sizeof(uint32_t));
    uint32_t const crc_recv = u32_from_be(&buf[ndata - sizeof(uint32_t)]);
    if (crc_calc != crc_recv) {
        ECBS_DBG_PRINTF("Fail to parse packet: crc mismatch, crc_calc=%08X crc_recv=%08X", crc_calc, crc_recv);
        return ER_2;
    }
    uint8_t const nfill = buf[4];
    uint8_t const seq = buf[5];
    int real_data_size = ndata - (ECBS__MIN_PACKET_SIZE + nfill);
    if (real_data_size < 0) {
        ECBS_DBG_PRINTF("Fail to parse packet: real_data_size(%i) < 0, ndata=%i nfill=%i", real_data_size, ndata, nfill);
        send_err(ecbs, 0, false, seq, ECBS_ERR__INTERNAL, ECBS_INTERNAL_ERR__REAL_DATA_SIZE_NEGATIVE);
        return ER_3;
    }
    struct Packet const packet = {
        .addr = buf[0],
        .pd = buf[1],
        .signal = u16_from_be(&buf[2]),
        .nfill = nfill,
        .seq = seq,
        .data = &buf[PACKET_DATA_POS],
        .ndata = (uint16_t)real_data_size,
    };

    if (!is_need_handle_addr(ecbs, packet.addr)) {
        ECBS_DBG_PRINTF("Cancel handle packet: addr %i does not need to be handled", packet.addr);
        return ER_4;
    }

    if ((packet.pd & ECBS__PD_DIR_MASK) != ECBS__PD_DIR_IS_REQ) {
        ECBS_DBG_PRINTF("Cancel handle packet: pd %02X is not REQUEST type", packet.pd);
        return ER_5;
    }

    ECBS_DBG_PRINTF("Packet received: addr=%u pd=%u sig=%u seq=%u ndata=%u",
        packet.addr, packet.pd,  packet.signal,  packet.seq,  packet.ndata);

    ecbs->tl_master_activity = ecbs->get_time_ms();

    if (packet.pd & ECBS__PD_IS_ENC_MASK) {
        if ((packet.ndata + packet.nfill) % 8 != 0) {
            ECBS_DBG_PRINTF("Fail to decrypt: ndata(%i) + nfill(%i) not multiple of 8", packet.ndata, packet.nfill);
            send_err(ecbs, 0, false, seq, ECBS_ERR__INTERNAL, ECBS_INTERNAL_ERR__DATA_SIZE_NOT_MULTIPLE_OF_BLOCK_SIZE);
            return ER_6;
        }
        if (!ecbs->is_enc_session) {
            ECBS_DBG_PRINT("Fail to decrypt: no enc session");
            send_err(ecbs, 0, false, seq, ECBS_ERR__NO_ENC_SESSION, 0);
            return ER_7;
        }
        TRY(raiden_decode_buf(ecbs->session_key, packet.data, packet.ndata + packet.nfill));
    }

    uint8_t const pd_type = packet.pd & ECBS__PD_TYPE_MASK;

    if (ECBS__PD_TYPE_READ == pd_type) {
        TRY(handle_read_request(ecbs, &packet));
    }
    else if (ECBS__PD_TYPE_WRITE == pd_type) {
        TRY(handle_write_request(ecbs, &packet));
    }
    else if (ECBS__PD_TYPE_WRITE_NO_ANSW == pd_type) {
        TRY(handle_write_no_answ_request(ecbs, &packet));
    }
    else if (ECBS__PD_TYPE_WRITE_AUTH_REQ == pd_type) {
        TRY(handle_write_auth_request(ecbs, &packet));
    }
    else if (ECBS__PD_TYPE_WRITE_WITH_AUTH == pd_type) {
        TRY(handle_write_with_auth_request(ecbs, &packet));
    }
    else if (ECBS__PD_TYPE_STREAM_OPEN == pd_type) {
        TRY(handle_stream_open_request(ecbs, &packet));
    }
    else if (ECBS__PD_TYPE_STREAM_CLOSE == pd_type) {
        TRY(handle_stream_close_request(ecbs, &packet));
    }
    else if (ECBS__PD_TYPE_ENC_OPEN == pd_type) {
        TRY(handle_enc_open_request(ecbs, &packet));
    }
    else {
        ECBS_DBG_PRINTF("Fail to handle packet: unknown PD_TYPE(%02X)", pd_type);
        send_err(ecbs, packet.signal, packet.pd & ECBS__PD_IS_ENC_MASK, seq,
            ECBS_ERR__INTERNAL, ECBS_INTERNAL_ERR__UNKNOWN_PD_TYPE);
        return ER_10;
    }

    return 0;
}

/// @brief Инициализация библиотеки.
/// @param[out] ecbs - Пустой, не инициализированный объект протокола
/// @param[in] addr - Адрес, на который будет откликаться устройство.
/// @param[in] get_time_ms - Коллбек для определения относительного времени в мс.
/// @param[in] read - Коллбек для чтения байт из аппаратного интерфейса, напр. UART.
///     Необходимо возвращать true, если байт считан, иначе false.
/// @param[in] write - Коллбек для записи байт в аппаратный интерфейс, напр. UART.
///     Необходимо возвращать true, если байт успешно записан, иначе false.
int ecbs__init(
    struct Ecbs* const ecbs,
    uint8_t const addr,
    uint32_t (*get_time_ms)(void),
    bool (*read)(uint8_t* byte),
    bool (*write)(uint8_t data))
{
    memset(ecbs, 0, sizeof(*ecbs));
    ecbs->addr = addr;
    ecbs->is_enc_init = false;
    ecbs->err_description_size = 0;
    ecbs->is_enc_init = false;
    ecbs->is_enc_session = false;
    framer7b__reset(&ecbs->framer);
    ecbs->read = read;
    ecbs->write = write;
    ecbs->get_time_ms = get_time_ms;
    ecbs->state = ECBS_STATE__RECEIVE;
    ecbs->stream_sig = NO_SIGNAL;
    ecbs->tl_read = 0;
    for (uint16_t i = 0; i < ECBS__MAX_SIG; i++) {
        ecbs->sig[i].sig = NO_SIGNAL;
    }
    return 0;
}

/// @brief Инициализировать продвинутую неблокирующую запись буфера.
/// @param ecbs - Объект протокола.
/// @param write_buf - Коллбек для отправки на запись в аппаратный интерфейс буфера целиком,  
///     необходимо возвращать true при принятии буфера на запись, иначе false.
/// @param get_write_state - Коллбек для проверки состояния записи буфера,
///     необходимо возвращать true, если запись завершена, иначе false.
int ecbs__init_write_buf(
    struct Ecbs* const ecbs,
    bool (*write_buf)(uint8_t const* data, uint16_t ndata),
    bool (*get_write_state)(void))
{
    ecbs->write_buf = write_buf;
    ecbs->get_write_state = get_write_state;
    return 0;
}

int ecbs__init_enc(struct Ecbs* const ecbs, const uint8_t auth_key[16], uint32_t (*get_rand)(void)) {
    memcpy(ecbs->auth_key, auth_key, sizeof(ecbs->auth_key));
    ecbs->get_rand = get_rand;
    ecbs->is_enc_init = true;
    return 0;
}

void ecbs__drop_enc_session(struct Ecbs* const ecbs) {
    ecbs->is_enc_session = false;
}

int ecbs__announce(struct Ecbs* const ecbs) {
    uint16_t packet_size = 0;
    TRY(make_packet(ecbs, false, ECBS__PD_TYPE_WRITE, ECBS_SIG__RESET, 0, 0, &packet_size));
    encode_packet_and_send_as_frame(ecbs, packet_size);
    return 0;
}

void ecbs__loop(struct Ecbs* const ecbs) {
    static uint8_t buf = 0;
    if (ECBS_STATE__RECEIVE == ecbs->state) {
        while (ecbs->read(&buf)) {
            ecbs->tl_read = ecbs->get_time_ms();
            int const framer_result = framer7b__push(&ecbs->framer, buf);
            if (framer_result > 0) {
                handle_packet(ecbs, framer_result);
                break;
            }
        }
        if (NO_SIGNAL != ecbs->stream_sig) {
            uint32_t time_ms = ecbs->get_time_ms();
            uint8_t const pub_period_ms = ecbs->sig[ecbs->stream_sig].stream_pub_period_ms;
            uint32_t const tl_pub_ms = ecbs->sig[ecbs->stream_sig].tl_stream_pub_ms;
            bool const is_time_to_send = IS_TIME_EXPIRED_EX(tl_pub_ms, pub_period_ms, time_ms);
            bool const is_allowed = IS_TIME_EXPIRED_EX(ecbs->tl_read, ECBS__ALLOW_SEND_STREAM_AFTER_RECV_MS, time_ms);
            if (is_time_to_send && is_allowed) {
                send_stream_data(ecbs);
            }
        }
    }
    else if (ECBS_STATE__SEND == ecbs->state) {
        if (ecbs->write_buf) {
            if (ecbs->is_buffer_sending) {
                if (ecbs->get_write_state()) {
                    ecbs->state = ECBS_STATE__RECEIVE;
                }
            } else {
                if (ecbs->write_buf(framer7b__get_frame_buf_to_send(&ecbs->framer), ecbs->nsend)) {
                    ecbs->is_buffer_sending = true;
                }
            }
        } else {
            if (ecbs->write(framer7b__get_frame_buf_to_send(&ecbs->framer)[ecbs->ptr])) {
                ecbs->ptr++;
                if (ecbs->ptr >= ecbs->nsend) {
                    ecbs->state = ECBS_STATE__RECEIVE;
                }
            }
        }
    }
}

/// @brief Добавить обработчик сигнала.
/// @param ecbs - указатель на объект библиотеки.
/// @param sig - номер сигнала.
/// @param protect_level - уровень защиты, 
///     #ECBS_PROTECT_LEVEL__NO - не требуется шифрование или авторизованная запись, обычный вариант,
///     #ECBS_PROTECT_LEVEL__ENC - требуется шифрование для чтения и записи,
///     #ECBS_PROTECT_LEVEL__ENC_AND_WRITE_AUTH - требуется шифрование для чтения и записи,
///     причем запись только с авторизацией, обеспечивает максимальную защиту.
/// @warning если требуется защищенная запись сигнала, но не требуется передавать данные(записывается 0 байт),
///     то в таком случае необходимо использовать только ECBS_PROTECT_LEVEL__ENC_AND_WRITE_AUTH уровень защиты.
///
/// @param read - коллбек-обработчик для операции чтения, должен возвращать количество считанных байт для передачи,
///     или -1 в случае ошибки.
/// @param write - коллбек-обработчик для операции записи, должен возвращать 0 в случае успеха и -1 в случае ошибки.
///
/// @return 0 в случае успеха, не 0 в случае ошибки.
int ecbs__add_sig(
    struct Ecbs* const ecbs,
    uint16_t const sig,
    enum EcbsProtectLevel const protect_level,
    int (*read)(uint16_t sig, uint8_t* buf),
    int (*write)(uint16_t sig, const uint8_t* data, uint16_t ndata))
{
    for (uint16_t i = 0; i < ECBS__MAX_SIG; i++) {
        if (sig == ecbs->sig[i].sig) {
            return ER_ALREADY;
        }
    }

    for (uint16_t i = 0; i < ECBS__MAX_SIG; i++) {
        if (NO_SIGNAL == ecbs->sig[i].sig) {
            ecbs->sig[i].sig = sig;
            ecbs->sig[i].read = read;
            ecbs->sig[i].write = write;
            ecbs->sig[i].is_stream_allowed = false;
            ecbs->sig[i].protect_level = protect_level;
            ecbs->sig[i].stream_pub_period_ms = 0;
            ecbs->sig[i].tl_stream_pub_ms = 0;
            return 0;
        }
    }

    return ER_NO_MEM;
}

int ecbs__allow_stream_at_sig(struct Ecbs* const ecbs, uint16_t const sig, uint8_t const stream_pub_period_ms) {
    struct EcbsSig* const sigd = find_sig(ecbs, sig);
    if (NULL == sigd) {
        return ER_NO_ENT;
    }
    if (NULL == sigd->read) {
        return ER_NOT_PERM;
    }
    sigd->is_stream_allowed = true;
    sigd->stream_pub_period_ms = stream_pub_period_ms;
    return 0;
}

int ecbs__force_pub_stream_at_sig(struct Ecbs* const ecbs, uint16_t const sig) {
    struct EcbsSig* const sigd = find_sig(ecbs, sig);
    if (NULL == sigd) {
        return -1;
    }
    sigd->tl_stream_pub_ms = 0;
    return 0;
}

bool ecbs__is_streaming(struct Ecbs const* const ecbs) {
    return ecbs->stream_sig != NO_SIGNAL;
}

uint32_t ecbs__get_tl_master_activity(struct Ecbs const* ecbs) {
    return ecbs->tl_master_activity;
}

void ecbs__add_err_description(struct Ecbs* const ecbs, char const* const fmt, ...) {
    va_list args = {0};
    va_start(args, fmt);
    uint8_t* const buf = framer7b__get_packet_buf_to_make(&ecbs->framer);
    int const rc = vsnprintf((char*)&buf[PACKET_DATA_POS + 1], ECBS__MAX_DATA_SIZE, fmt, args);
    va_end(args);
    if (rc > 0) {
        ecbs->err_description_size = (uint16_t)rc;
    }
}
