#ifndef _ECB_SLAVE_APPLVL_H_
#define _ECB_SLAVE_APPLVL_H_

#include "ecb-slave.h"

int ecbs_applvl__init_log(struct Ecbs* ecbs, uint16_t buf_size);
void ecbs_applvl__log(char const* str);

#endif
