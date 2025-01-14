#ifndef _ECB_SLAVE_APPLVL_H_
#define _ECB_SLAVE_APPLVL_H_

#include "ecb-slave.h"

enum {
	ECBS_APPLVL__LOG_BUF_SIZE = ECBS__MAX_DATA_SIZE - 1,
};

static_assert((int)ECBS_APPLVL__LOG_BUF_SIZE < (int)ECBS__MAX_DATA_SIZE);

int ecbs_applvl__init_log(struct Ecbs* ecbs);
void ecbs_applvl__log(char const* str);

#endif
