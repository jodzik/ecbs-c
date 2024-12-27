#ifndef ECBS
#define ECBS

#ifdef __cplusplus
extern "C" {
#endif

#include "framer7b.h"
#include "../safe-c/safe_c.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>


// #define ECBS_DEBUG_EN                   1

#if ECBS_DEBUG_EN

#define ECBS_DBG_PRINT(fmt) DBG_LOG(fmt)
#define ECBS_DBG_PRINTF(fmt, ...) DBG_LOGf(fmt, __VA_ARGS__)

#else
#define ECBS_DBG_PRINT(fmt) LOG_MOCK(fmt)
#define ECBS_DBG_PRINTF(fmt, ...) LOG_MOCK(fmt)
#endif


// Settings
enum {
    ECBS__MAX_SIG = 32,
    ECBS__ALLOW_SEND_STREAM_AFTER_RECV_MS = 10,
};

enum {
    ECBS__BROADCAST_ADDR = 0x00,
    ECBS__MIN_PACKET_SIZE = 10,
    ECBS__MAX_DATA_SIZE = (int)FRAMER7B__DATA_SIZE - (int)ECBS__MIN_PACKET_SIZE,
    ECBS__DEVICE_ID_SIZE = 16,
    ECBS__APP_NAME_SIZE = 32,
    ECBS__SERIAL_SIZE = 32,
    ECBS__PLATFORM_NAME_SIZE = 32,
    ECBS__APP_VERSION_SIZE = 3,
};

enum {
    ECBS_SIG__RESET = 0,
    ECBS_SIG__INFO = 1,
    ECBS_SIG__ADDR = 2,
    ECBS_SIG__SERIAL = 13,
    ECBS_SIG__AUTH_KEY = 14,
    ECBS_SIG__PICK = 15,
    
    ECBS_SIG_BOOT__BEGIN = 16,
    ECBS_SIG_BOOT__END = 17,
    ECBS_SIG_BOOT__FW_KEY = 19,
    ECBS_SIG_BOOT__WRITE = 20,
    ECBS_SIG_BOOT__APP_INFO = 22,
    ECBS_SIG_BOOT__GO_APP = 23,
};

enum {
    ECBS_TLV__NAME = 1,         // String
    ECBS_TLV__VERSION = 2,      // [u8;3]
    ECBS_TLV__SERIAL = 3,       // String
    ECBS_TLV__TEST_PHRASE = 4,  // String
    ECBS_TLV__FW_SIZE = 5,      // u32
    ECBS_TLV__FW_CRC32 = 6,      // u32
    ECBS_TLV__PLATFORM_NAME = 8, // String
    ECBS_TLV__BOARD_REVISION = 9, // u16
    ECBS_TLV__DEVICE_ID = 10,    // [u8;16]
    ECBS_TLV__AUTH_KEY = 11,     // [u8;#RAIDEN__KEY_SIZE]
    ECBS_TLV__FW_KEY = 12,       // [u8;#RAIDEN__KEY_SIZE]
    ECBS_TLV__ADDR = 13,         // u8
    ECBS_TLV__IS_SERIAL_PERMANENT = 14, // bool
};

typedef enum EcbsErr {
    ECBS_ERR__APP = 0x01,
    ECBS_ERR__NO_SIG = 0x02,
    ECBS_ERR__NO_OPERATION = 0x03,
    ECBS_ERR__ENC_REQUIRED = 0x04,
    ECBS_ERR__AUTH_REQUIRED = 0x05,
    ECBS_ERR__NO_ENC_SESSION = 0x06,
    ECBS_ERR__INTERNAL = 0x07,
    ECBS_ERR__INCORRECT_SIGN = 0x08,
    ECBS_ERR__ENC_NOT_SUPPORTED = 0x09,
} EcbsErr;

typedef enum EcbsInternalErr {
    ECBS_INTERNAL_ERR__ENC_NOT_ALLOWED = 1,
    ECBS_INTERNAL_ERR__NO_SIGN = 2,
    ECBS_INTERNAL_ERR__REAL_DATA_SIZE_NEGATIVE = 3,
    ECBS_INTERNAL_ERR__DATA_SIZE_NOT_MULTIPLE_OF_BLOCK_SIZE = 4,
    ECBS_INTERNAL_ERR__UNKNOWN_PD_TYPE = 5,
} EcbsInternalErr;

typedef enum EcbsState {
    ECBS_STATE__RECEIVE,
    ECBS_STATE__SEND
} EcbsState;

typedef enum EcbsProtectLevel {
    ECBS_PROTECT_LEVEL__NO,
    ECBS_PROTECT_LEVEL__ENC,
    ECBS_PROTECT_LEVEL__ENC_AND_WRITE_AUTH,
} EcbsProtectLevel;

typedef struct EcbsSig {
    int sig;
    enum EcbsProtectLevel protect_level;
    uint8_t stream_pub_period_ms;
    uint32_t tl_stream_pub_ms;
    bool is_stream_allowed;
    int (*read)(uint16_t sig, uint8_t* buf);
    int (*write)(uint16_t sig, const uint8_t* data, uint16_t ndata);
} EcbsSig;

typedef struct Ecbs {
    Framer7b framer;
    uint8_t addr;
    uint8_t auth_key[16];
    bool is_enc_init;
    uint8_t session_key[16];
    bool is_enc_session;
    EcbsState state;
    uint16_t ptr;
    uint16_t nsend;
    EcbsSig sig[ECBS__MAX_SIG];
    uint16_t err_description_size;
    uint8_t write_auth_rand_key[sizeof(uint64_t)];
    int stream_sig;
    uint32_t tl_read;
    uint32_t tl_master_activity;
    bool is_buffer_sending;

    bool (*read)(uint8_t* byte);
    bool (*write)(uint8_t data);
    uint32_t (*get_rand)(void);
    uint32_t (*get_time_ms)(void);
    bool (*write_buf)(uint8_t const* data, uint16_t ndata);
    bool (*get_write_state)(void);
} Ecbs;


int ecbs__init(
    struct Ecbs* ecbs,
    uint8_t addr,
    uint32_t (*get_time_ms)(void),
    bool (*read)(uint8_t* byte),
    bool (*write)(uint8_t data));

int ecbs__init_enc(struct Ecbs* ecbs, const uint8_t auth_key[16], uint32_t (*get_rand)(void));

int ecbs__init_write_buf(
    struct Ecbs* ecbs,
    bool (*write_buf)(uint8_t const* data, uint16_t ndata),
    bool (*get_write_state)(void));

int ecbs__drop_enc_session(struct Ecbs* ecbs);

int ecbs__announce(struct Ecbs* ecbs);

int ecbs__add_sig(
    struct Ecbs* ecbs,
    uint16_t sig,
    enum EcbsProtectLevel protect_level,
    int (*read)(uint16_t sig, uint8_t* buf),
    int (*write)(uint16_t sig, const uint8_t* data, uint16_t ndata));

int ecbs__allow_stream_at_sig(struct Ecbs* ecbs, uint16_t sig, uint8_t stream_pub_period_ms);
int ecbs__force_pub_stream_at_sig(struct Ecbs* ecbs, uint16_t sig);
int ecbs__is_streaming(struct Ecbs const* ecbs, bool* result);

int ecbs__get_tl_master_activity(struct Ecbs const* ecbs, uint32_t* result);

int ecbs__add_err_description(struct Ecbs* ecbs, char const* const fmt, ...);

int ecbs__loop(struct Ecbs* ecbs);

#ifdef __cplusplus
}
#endif

#endif
