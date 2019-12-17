#ifndef BESS_MODULES_LRO_H_
#define BESS_MODULES_LRO_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../seg_config.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/xpass.h"
#include "../utils/checksum.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::Xpass;
using bess::utils::be16_t;
using bess::utils::be32_t;

struct lro_flow {
  bess::Packet *pkt; /* NULL if empty */
  uint64_t tsc;

  uint32_t src_addr;
  uint32_t dst_addr;
  uint16_t src_port;
  uint16_t dst_port;

  uint32_t next_seq;  /* in host order */

  /* Offset of (inner, if encapsulated) IP/TCP. */
  uint16_t ip_offset;
  uint16_t tcp_offset;
};

class LRO final : public Module {
public:
  static const gate_idx_t kNumIGates = 1;
  static const gate_idx_t kNumOGates = 1;
  struct lro_flow *worker_flows;
  
  void ProcessBatch(bess::PacketBatch *batch) override;
  struct task_result RunTask(void *arg) override;
  CommandResponse Init(const bess::pb::EmptyArg &arg);
  void BatchPush(bess::PacketBatch *batch, bess::Packet *pkt);
  void PopXpass(bess::Packet *pkt, Ipv4 *iph, uint16_t payload_offset);
  void LroFlushFlow(bess::PacketBatch *batch, struct lro_flow *flow);
  int LroEvictFlow(bess::PacketBatch *batch, struct lro_flow *flows);
  void LroInitFlow(struct lro_flow *flow, bess::Packet *pkt, 
                   uint16_t ip_offset, uint16_t tcp_offset);
  void LroAppendPkt(bess::PacketBatch *batch, struct lro_flow *flow, 
                    bess::Packet *pkt, uint16_t ip_offset, uint16_t tcp_offset);
  void DoLro(bess::PacketBatch *batch, bess::Packet *pkt);
};
#endif // BESS_MODULES_LRO_H_
