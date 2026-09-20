#ifndef _ECBS_APPLVL_H_
#define _ECBS_APPLVL_H_

#include "ecbs.h"

typedef enum EcbsStdDataId {
    ECBS_STD_DATA_ID__RESET = 65280,
    ECBS_STD_DATA_ID__INFO = 65281,
    ECBS_STD_DATA_ID__PICK = 65282,
    ECBS_STD_DATA_ID__ADDR = 65283,
    ECBS_STD_DATA_ID__SERIAL = 65284,
} EcbsStdDataId;

enum {
    ECBS_DEVICE_INFO__DEVICE_ID_SIZE = 16,
    ECBS_DEVICE_INFO__NAME_SIZE = 64,
    ECBS_DEVICE_INFO__SERIAL_SIZE = 64,
    ECBS_DEVICE_INFO__FW_VERSION_SIZE = 3,
    ECBS_DEVICE_INFO__BOARD_REVISION_SIZE = 2,
};

typedef enum EcbsDeviceInfoTlv {
    ECBS_DEVICE_INFO_TLV__NAME = 1,           // String
    ECBS_DEVICE_INFO_TLV__FW_VERSION = 2,     // [u8;3]
    ECBS_DEVICE_INFO_TLV__SERIAL = 3,         // String
    ECBS_DEVICE_INFO_TLV__BOARD_REVISION = 4, // [u8;2]
    ECBS_DEVICE_INFO_TLV__DEVICE_ID = 5,      // [u8;16]
} EcbsDeviceInfoTlv;

#endif
