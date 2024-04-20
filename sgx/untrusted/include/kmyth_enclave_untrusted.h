#ifndef _KMYTH_ENCLAVE_UNTRUSTED_H_
#define _KMYTH_ENCLAVE_TRUSTED_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "sgx_urts.h"

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include ENCLAVE_HEADER_UNTRUSTED

#include "msg_util.h"

#ifdef __cplusplus
}
#endif

#endif
