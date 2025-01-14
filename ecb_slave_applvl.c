#include "ecb_slave_applvl.h"

#include <stdlib.h>


static struct Ecbs* g_ecbs = NULL;
static char g_log_buf[ECBS_APPLVL__LOG_BUF_SIZE] = {0};
static uint16_t g_log_buf_real_size = 0;


static int sig_log_r(uint16_t const sig, uint8_t* const buf) {
    int const rc = g_log_buf_real_size;
	UNUSED(sig);
    memcpy(buf, g_log_buf, g_log_buf_real_size);
    g_log_buf_real_size = 0;
    return rc;
}

int ecbs_applvl__init_log(struct Ecbs* const ecbs) {
	ASSERT(NULL != ecbs, ER_1 + ER_INVAL);
	TRY(ecbs__add_sig(ecbs, ECBS_SIG__LOG, ECBS_PROTECT_LEVEL__NO, sig_log_r, NULL));
	TRY(ecbs__allow_stream_at_sig(ecbs, ECBS_SIG__LOG, 255));
	g_ecbs = ecbs;

	return 0;
}

void ecbs_applvl__log(char const* const str) {
	size_t len = strnlen(str, SAFE_C__VPRINTF_BUF - 1);
	if (len > sizeof(g_log_buf)) {
		len = sizeof(g_log_buf);
	}
	if (len > (size_t)(sizeof(g_log_buf) - g_log_buf_real_size)) {
		g_log_buf_real_size = 0;
	}
	memcpy(&g_log_buf[g_log_buf_real_size], str, len);
	g_log_buf_real_size += (uint16_t)len;

	if (g_ecbs) {
		ecbs__force_pub_stream_at_sig(g_ecbs, ECBS_SIG__LOG);
	}
}
