#ifndef BESS_SEG_CONFIG_H_
#define BESS_SEG_CONFIG_H_

#include "../xpass_config.h"

#define FRAME_SIZE (1514 - XPASS_BYTES) // 1514(MTU) - 12(Xpass)
#define MAX_LFRAME 8192
#define MAX_LRO_FLOWS 16

#endif // BESS_SEG_CONFIG_H_
