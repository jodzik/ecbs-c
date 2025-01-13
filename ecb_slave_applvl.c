#include "ecb_slave_applvl.h"

#include <stdlib.h>


static struct Ecbs* g_ecbs = NULL;
static char* g_log_buf = NULL;
static uint16_t g_log_buf_size = 0;
static uint16_t g_log_buf_real_size = 0;


static int sig_log_r(uint16_t const sig, uint8_t* const buf) {
    int const rc = g_log_buf_real_size;
	UNUSED(sig);
    memcpy(buf, g_log_buf, g_log_buf_real_size);
    g_log_buf_real_size = 0;
    return rc;
}

int ecbs_applvl__init_log(struct Ecbs* const ecbs, uint16_t const buf_size) {
	ASSERT(NULL != ecbs, ER_1 + ER_INVAL);
	ASSERT(buf_size > 0, ER_2 + ER_INVAL);
	ASSERT(buf_size < ECBS__MAX_DATA_SIZE, ER_3 + ER_INVAL);
	g_log_buf = malloc(buf_size);
	ASSERT(NULL != g_log_buf, ER_NO_MEM);
	g_log_buf_size = buf_size;
	TRY(ecbs__add_sig(ecbs, ECBS_SIG__LOG, ECBS_PROTECT_LEVEL__NO, sig_log_r, NULL));
	TRY(ecbs__allow_stream_at_sig(ecbs, ECBS_SIG__LOG, 255));
	g_ecbs = ecbs;

	return 0;
}

void ecbs_applvl__log(char const* const str) {
	if (g_ecbs) {
		size_t len = strnlen(str, SAFE_C__VPRINTF_BUF - 1);
		if (len > g_log_buf_size) {
			len = g_log_buf_size;
		}
		if (len > (size_t)(g_log_buf_size - g_log_buf_real_size)) {
			g_log_buf_real_size = 0;
		}
		memcpy(&g_log_buf[g_log_buf_real_size], str, len);
		g_log_buf_real_size += (uint16_t)len;
		ecbs__force_pub_stream_at_sig(g_ecbs, ECBS_SIG__LOG);
	}
}
