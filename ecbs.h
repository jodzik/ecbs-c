#ifndef _ECBS_H_
#define _ECBS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <framer7b.h>
#include <safe_c.h>

#include <stdint.h>
#include <stdbool.h>

typedef struct EcbsRequestToken {
    uint8_t pd; // request packet descriptor
    uint8_t addr; // request destination addr
    uint32_t crc32; // CRC32 of the request packet
} EcbsRequestToken;

typedef uint16_t EcbsDataId;
typedef uint8_t EcbsAddr;

/** Endpoint read callback, see #ecbs__register_endpoint for the contract. */
typedef int (*EcbsEndpointRead)(EcbsDataId id, EcbsRequestToken token, void* user_data);
/** Endpoint write callback, see #ecbs__register_endpoint for the contract. */
typedef int (*EcbsEndpointWrite)(EcbsDataId id, EcbsRequestToken token, const uint8_t* data, uint16_t data_size,
    void* user_data);

enum {
    ECBS__BROADCAST_ADDR = 0xFF,
    ECBS__MIN_PACKET_SIZE = 10,
    ECBS__MAX_PAYLOAD_SIZE = CONFIG_ECBS_MAX_PAYLOAD_SIZE,
    ECBS__MAX_ENDPOINTS = CONFIG_ECBS_MAX_ENDPOINTS,
};

/// Index of the endpoint that owes the answer, if there is no such - #ECBS__NO_PENDING_EP.
#define ECBS__NO_PENDING_EP UINT8_MAX

#if CONFIG_ECBS_MAX_ENDPOINTS >= UINT8_MAX
#error "CONFIG_ECBS_MAX_ENDPOINTS must be less than UINT8_MAX."
#endif

typedef enum EcbsProtoErr {
    ECBS_PROTO_ERR__INVALID_PAYLOAD_SIZE = 0x01,
    ECBS_PROTO_ERR__INVALID_TRANSACTION_ID = 0x02,
    ECBS_PROTO_ERR__BUSY = 0x03, // Reserved by the protocol, not sent by this implementation.
    ECBS_PROTO_ERR__TRANSACTION_CONFLICT = 0x04,
} EcbsProtoErr;

typedef enum EcbsAppErr {
    ECBS_APP_ERR__NO_DATA_ID = 0x01,
    ECBS_APP_ERR__NO_OPERATION = 0x02,
} EcbsAppErr;

typedef enum EcbsState {
    ECBS_STATE__RECEIVE,
    ECBS_STATE__SEND,
    ECBS_STATE__WAIT_ANSWER, // Wait until application prepare answer and call ecbs__send_*_answer().
} EcbsState;

typedef enum EcbsWriteStatus {
    ECBS_WRITE_STATUS__COMPLETED,
    ECBS_WRITE_STATUS__PROCEEDED,
    ECBS_WRITE_STATUS__FAILED,
} EcbsWriteStatus;

typedef struct EcbsEndpoint {
    bool is_used;
    EcbsDataId id;
    void* user_data;
    EcbsEndpointRead read;
    EcbsEndpointWrite write;
    uint16_t timeout_ms; // max time for the application to prepare an answer, cannot be zero
} EcbsEndpoint;

typedef struct Ecbs {
    uint8_t rx_buf[FRAMER7B_FRAME_SIZE(ECBS__MAX_PAYLOAD_SIZE + ECBS__MIN_PACKET_SIZE)];
    Framer7bReceiver framer;
    // contain last answer, kept for the request retry deduplication
    uint8_t tx_buf[FRAMER7B_FRAME_SIZE(ECBS__MAX_PAYLOAD_SIZE + ECBS__MIN_PACKET_SIZE)];

    EcbsAddr addr;
    EcbsEndpoint endpoints[ECBS__MAX_ENDPOINTS];
    int (*read)(uint8_t* buf, uint16_t buf_size);
    int (*write)(uint8_t const* data, uint16_t ndata);
    uint64_t (*get_time_ms)(void);
    enum EcbsWriteStatus (*get_write_status)(void); // optional, NULL if transport write is synchronous

    EcbsState state;
    EcbsRequestToken last_request_token; // token of last request with our addr
    uint16_t last_tid; // transaction_id of last request with our addr
    uint16_t last_data_id; // data_id of last request with our addr
    uint16_t answer_size; // size of the last answer frame in tx_buf, 0 if it is not stored
    uint8_t pending_ep; // index of the endpoint that owes the answer, ECBS__NO_PENDING_EP if none
    uint16_t send_ptr;
    uint16_t send_total; // total count of bytes needed to send in tx_buf
    uint64_t tl_receive; // time of last any data receive from serial interface
    uint64_t tl_master_activity; // time of last any approved master activity(any valid request packet with correct crc)
    uint64_t tl_request; // time of the pending request receive
} Ecbs;

/** @brief Init ecb slave instance.
 *
 * @param[in] get_time_ms - get uptime callback.
 * @param[in] read read received by serial interface data,
 *                 return 0 if no data available, return negative if error, else return read bytes count.
 * @param[in] write write data to serial interface callback,
 *                  return negative if error, else return count of really written bytes.
 * @param[in] get_write_status optional(may be NULL) callback for transports with asynchronous write,
 *                  polled after all bytes accepted by write(), must return the status of that write.
 *                  If NULL, the send is considered complete immediately after write().
 */
int ecbs__init(
    struct Ecbs* ecbs,
    EcbsAddr addr,
    uint64_t (*get_time_ms)(void),
    int (*read)(uint8_t* buf, uint16_t buf_size),
    int (*write)(uint8_t const* data, uint16_t ndata),
    enum EcbsWriteStatus (*get_write_status)(void)) __nonnull((1, 3, 4, 5));

/** @brief Send announce(generic reset answer):
 * TYPE=WRITE answer packet with transaction_id=0, data_id=RESET, empty payload.
 * Should be called on system startup.
 *
 * @return 0 if sended, else #ErrorCodes: #ER_BUSY if a transaction is in progress.
 */
int ecbs__announce(struct Ecbs* ecbs) __nonnull((1));

/** @brief Register endpoint for the data_id.
 *
 * Endpoint callbacks contract:
 * - return 0 - the application must call ecbs__send_read_answer()/ecbs__send_write_answer()
 *   or ecbs__send_app_error_answer() later(within timeout_ms), inside or outside the callback;
 * - return < 0 and no answer queued inside the callback - the library immediately sends
 *   APP_ERR answer with error_code = (uint8_t)(-return_code) and empty description.
 *
 * @param[in] timeout_ms - max time to prepare the answer for this endpoint, cannot be zero,
 *                          should be slightly less than the master side timeout.
 * @param[in] user_data - opaque pointer for the callbacks, may be NULL.
 * @param[in] read_callback, write_callback - at least one must be non-NULL.
 *
 * @return 0 if registered, else #ErrorCodes.
 */
int ecbs__register_endpoint(
    struct Ecbs* ecbs,
    EcbsDataId id,
    uint16_t timeout_ms,
    void* user_data,
    EcbsEndpointRead read_callback,
    EcbsEndpointWrite write_callback) __nonnull((1));

/** @brief Get the time of the last approved master activity(any valid request packet, any addr). */
int ecbs__get_tl_master_activity(struct Ecbs const* ecbs, uint64_t* result) __nonnull((1, 2));

/** @brief Send WRITE answer(empty payload) for the pending request.
 *
 * @note can be called inside and outside read/write endpoint callback.
 * @note ecbs__process() and ecbs__send_*_answer() are not thread safe, serialize it by the caller.
 *
 * @param[in] token must be equal to the token passed in the endpoint callback.
 *
 * @return 0 if answer queued, else #ErrorCodes:
 *         #ER_BUSY - another answer is being sent,
 *         #ER_TIMEDOUT - the request is expired or terminated,
 *         #ER_INVAL - token mismatch.
 */
int ecbs__send_write_answer(struct Ecbs* ecbs, EcbsRequestToken token) __nonnull((1));

/** @brief Send READ answer for the pending request, see #ecbs__send_write_answer.
 *
 * @param[in] data answer payload, may be NULL if data_size is zero.
 * @param[in] data_size answer payload size, cannot be greater than #ECBS__MAX_PAYLOAD_SIZE.
 *
 * @return 0 if answer queued, else #ErrorCodes, see #ecbs__send_write_answer, also
 *         #ER_ENT_TOO_BIG - data_size too big.
 */
int ecbs__send_read_answer(
    struct Ecbs* ecbs,
    EcbsRequestToken token,
    uint8_t const* data,
    uint16_t data_size) __nonnull((1));

/** @brief Send APP_ERR answer for the pending request, see #ecbs__send_write_answer.
 *
 * @param[in] error_code - application error code.
 * @param[in] fmt - optional(may be NULL) UTF-8 description format, truncated to 127 chars + NULL.
 */
int ecbs__send_app_error_answer(
    struct Ecbs* ecbs,
    EcbsRequestToken token,
    uint8_t error_code,
    char const* const fmt, ...) __nonnull((1));

/** @brief Send data asynchronously as PUB_DATA packet with transaction_id=0.
 *
 * @warning This function allowed only in 1-1 and full duplex connect scheme.
 * @warning Allowed only if no transaction is in progress, the stored last answer
 *          is discarded(tx buffer is reused).
 *
 * @return 0 if sended, else #ErrorCodes: #ER_BUSY if a transaction is in progress,
 *         #ER_ENT_TOO_BIG if data_size too big.
 */
int ecbs__send_async(struct Ecbs* ecbs, EcbsDataId data_id, uint8_t const* data,
    uint16_t data_size) __nonnull((1));

/** @brief Process the slave state machine, call it periodically.
 *
 * @return 0 or transport #ErrorCodes(negative read/write result).
 */
int ecbs__process(struct Ecbs* ecbs) __nonnull((1));

#ifdef __cplusplus
}
#endif

#endif // _ECBS_H_
