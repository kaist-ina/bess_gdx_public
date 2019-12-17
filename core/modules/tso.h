#ifndef BESS_MODULES_TSO_H_
#define BESS_MODULES_TSO_H_

#include "../module.h"
#include "../seg_config.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/xpass.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::Xpass;
using bess::utils::be16_t;
using bess::utils::be32_t;

class TSO final : public Module {
public:
  TSO() {}

  static const gate_idx_t kNumIGates = 1;
  static const gate_idx_t kNumOGates = 1;

  void ProcessBatch(bess::PacketBatch *batch) override;
  void BatchPush(bess::PacketBatch *batch, bess::Packet *pkt); 
  void PushXpass(bess::Packet *pkt, Ipv4 *iph, uint16_t payload_offset);

  void DoTso(bess::PacketBatch *batch, bess::Packet *pkt);
};

#endif // BESS_MODULES_TSO_H_
