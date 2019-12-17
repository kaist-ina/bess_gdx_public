#ifndef BESS_UTILS_XPASS_H_
#define BESS_UTILS_XPASS_H_

#include "../xpass_config.h"

namespace bess {
namespace utils {

struct[[gnu::packed]] Xpass {
  enum XPassPacketType : uint16_t {
    kCreditRequest = 0x01,
    kCreditStop = 0x02,
    kCredit = 0x03,
    kData = 0x04,
  };

  uint16_t packet_type;
  uint16_t credit_seq_num;
  uint64_t time;
};

static_assert(std::is_pod<Xpass>::value, "not a POD type");
static_assert(sizeof(Xpass) == XPASS_BYTES, "struct Xpass is incorrect");

}  // namespace utils
}  // namespace bess

#endif  // BESS_UTILS_XPASS_H_
