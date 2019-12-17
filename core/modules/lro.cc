#include "lro.h"
#include "../mem_alloc.h"
#include "../utils/time.h"

CommandResponse LRO::Init(const bess::pb::EmptyArg &){
  worker_flows = (lro_flow *)mem_alloc(sizeof(struct lro_flow) * MAX_LRO_FLOWS);
  assert(worker_flows);

  task_id_t tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID) {
    return CommandFailure(ENOMEM, "task creation failed");
  }
  return CommandSuccess();
}

void LRO::ProcessBatch(bess::PacketBatch *batch) {
  bess::PacketBatch new_batch_object = bess::PacketBatch();
  bess::PacketBatch *new_batch = &new_batch_object;
  new_batch->clear();
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    DoLro(new_batch, pkt);
  }
  RunNextModule(new_batch);
}

struct task_result LRO::RunTask(void *) {
  bess::PacketBatch batch;
  uint64_t now = rdtsc();
  uint64_t bytes = 0;
  uint32_t ret = 0;
  int i;
  batch.clear();
  for (i = 0; i < MAX_LRO_FLOWS; i++) {
    if (!worker_flows[i].pkt)
      continue;

    /* If older than 100us, flush.
     * While 100us seems too much, it is not.
     * (we immediately flush packets if PSH is seen) */

    if (tsc_to_us(now - worker_flows[i].tsc) > 100.) {
      bytes += worker_flows[i].pkt->total_len();
      LroFlushFlow(&batch, &worker_flows[i]);
      ret++;
    }
  }
  if (ret)
    RunNextModule(&batch);

  return {
      .block = false,
      .packets = ret,
      .bits = bytes * 8};
}

void LRO::BatchPush(bess::PacketBatch *batch, bess::Packet *pkt) {
  batch->add(pkt);
  if (batch->full()) {
    RunNextModule(batch);
    batch->clear();
  }
}

void LRO::PopXpass(bess::Packet *pkt, Ipv4 *iph, uint16_t payload_offset) {
  uint8_t *head;

  if (unlikely((head = static_cast<uint8_t *>(pkt->adj(XPASS_BYTES))) == nullptr)) {
    LOG(WARNING) << "[LRO] Fatal Error: Cannot adj packet.";
    return;
  }

  iph->length = be16_t(iph->length.value() - XPASS_BYTES);
  memmove(head, head - XPASS_BYTES, payload_offset - XPASS_BYTES);
}

void LRO::LroFlushFlow(bess::PacketBatch *batch, struct lro_flow *flow) {
  /* No checksum calculation here (Use checksum modules).  No VXLAN Support */
  Ipv4 *iph = flow->pkt->head_data<Ipv4 *>(flow->ip_offset);
  Tcp *tcph = flow->pkt->head_data<Tcp *>(flow->tcp_offset);

  iph->checksum = CalculateIpv4Checksum(*iph);
  tcph->checksum = CalculateIpv4TcpChecksum(*iph, *tcph);
  BatchPush(batch, flow->pkt);
  flow->pkt = NULL;
}

int LRO::LroEvictFlow(bess::PacketBatch *batch, struct lro_flow *flows) {
  int oldest = 0;
  int i;

  /* We assume no slots are empty */
  for (i = 1; i < MAX_LRO_FLOWS; i++) {
    if (flows[oldest].tsc > flows[i].tsc)
      oldest = i;
  }

  LroFlushFlow(batch, &flows[oldest]);
  return oldest;
}

void LRO::LroInitFlow(struct lro_flow *flow, bess::Packet *pkt, uint16_t ip_offset, uint16_t tcp_offset) {
  Ipv4 *iph = pkt->head_data<Ipv4 *>(ip_offset);
  Tcp *tcph = pkt->head_data<Tcp *>(tcp_offset);
  uint16_t payload_offset = tcp_offset + ((tcph->offset) << 2) + XPASS_BYTES;
  uint32_t payload_size = pkt->total_len() - payload_offset;
//  assert(pkt->total_len() == pkt->head_len());

  flow->pkt = pkt;
  flow->tsc = rdtsc();
  flow->src_addr = iph->src.value();
  flow->dst_addr = iph->dst.value();
  flow->src_port = tcph->src_port.value();
  flow->dst_port = tcph->dst_port.value();
  flow->next_seq = tcph->seq_num.value() + payload_size;

  flow->ip_offset = ip_offset;
  flow->tcp_offset = tcp_offset;

  PopXpass(flow->pkt, iph, payload_offset);
}

void LRO::LroAppendPkt(bess::PacketBatch *batch, struct lro_flow *flow, bess::Packet *pkt, uint16_t ip_offset, uint16_t tcp_offset) {
  Ipv4 *iph = pkt->head_data<Ipv4 *>(ip_offset);
  Tcp *tcph = pkt->head_data<Tcp *>(tcp_offset);
//  Xpass *xph = pkt->head_data<Xpass *>(tcp_offset + ((tcph->offset) << 2));
//  void *data = xph + 1;
  
  uint32_t payload_offset = tcp_offset + ((tcph->offset) << 2) + XPASS_BYTES;
  uint32_t payload_size = pkt->total_len() - payload_offset;
//  assert(pkt->total_len() == pkt->head_len());
  uint32_t new_seq = tcph->seq_num.value();

  Ipv4 *old_ip = flow->pkt->head_data<Ipv4 *>(flow->ip_offset);
  Tcp *old_tcp = flow->pkt->head_data<Tcp *>(flow->tcp_offset);

  assert(pkt->is_linear());

  if (flow->next_seq != new_seq || old_tcp->ack_num.value() != tcph->ack_num.value()) {
    LroFlushFlow(batch, flow);
    PopXpass(pkt, iph, payload_offset);
    
    iph = pkt->head_data<Ipv4 *>(ip_offset);
    tcph = pkt->head_data<Tcp *>(tcp_offset);

    iph->checksum = CalculateIpv4Checksum(*iph);
    tcph->checksum = CalculateIpv4TcpChecksum(*iph, *tcph);

    BatchPush(batch, pkt);
    return;
  }

  if (flow->pkt->total_len() + payload_size > MAX_LFRAME) {
    LroFlushFlow(batch, flow);
    LroInitFlow(flow, pkt, ip_offset, tcp_offset);
    return;
  }

  old_ip->length = be16_t(old_ip->length.value() + payload_size);
  old_tcp->flags |= tcph->flags;
  old_ip->type_of_service |= (iph->type_of_service & 0x3);

  pkt->adj(payload_offset);
  bess::utils::Copy(flow->pkt->append(payload_size), pkt->head_data(), payload_size);
  bess::Packet::Free(pkt);

  /* if TCP flags other than ACK are on, flush */
  if (old_tcp->flags & 0xef) {
    LroFlushFlow(batch, flow);
    return;
  }

  flow->next_seq = new_seq + payload_size;
}

void LRO::DoLro(bess::PacketBatch *batch, bess::Packet *pkt) {
  uint16_t ip_offset;
  uint16_t tcp_offset;
  uint16_t payload_offset;

  int free_slot = -1;
  int i;

  /* skip checking whether packets are from physical intefaces and has correct csum */
  Ethernet *eth = pkt->head_data<Ethernet *>();
  void *data = eth + 1;

  if (eth->ether_type != be16_t(Ethernet::Type::kIpv4)) {
    BatchPush(batch, pkt);
    return;
  }

  Ipv4 *iph = reinterpret_cast<Ipv4 *>(data);
  size_t ip_bytes = (iph->header_length) << 2;
  
  if (iph->protocol != Ipv4::Proto::kTcp) {
    BatchPush(batch, pkt);
    return;
  }

  Tcp *tcph = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(iph) + ip_bytes);

  ip_offset = reinterpret_cast<uint8_t *>(iph) - reinterpret_cast<uint8_t *>(eth);
  tcp_offset = reinterpret_cast<uint8_t *>(tcph) - reinterpret_cast<uint8_t *>(eth);
  payload_offset = tcp_offset + ((tcph->offset) << 2) + XPASS_BYTES;

  for (i = 0; i < MAX_LRO_FLOWS; i++) {
    if (!worker_flows[i].pkt) {
      if (free_slot == -1)
        free_slot = i;
      continue;
    }
    if (worker_flows[i].src_addr == iph->src.value() &&
        worker_flows[i].dst_addr == iph->dst.value() &&
        worker_flows[i].src_port == tcph->src_port.value() &&
        worker_flows[i].dst_port == tcph->dst_port.value()) {
      LroAppendPkt(batch, &worker_flows[i], pkt, ip_offset, tcp_offset);
      return;
    }
  }

  /* Here, there is no existing flow for the TCP packet. */
  /* Should we buffer this packet? */
  if (tcph->flags & 0xef) {
    /* Bypass if there are any flags other than ack */
    PopXpass(pkt, iph, payload_offset);
    iph = pkt->head_data<Ipv4 *>(ip_offset);
    tcph = pkt->head_data<Tcp *>(tcp_offset);

    iph->checksum = CalculateIpv4Checksum(*iph);
    tcph->checksum = CalculateIpv4TcpChecksum(*iph, *tcph);

    BatchPush(batch, pkt);
    return;
  }

  if (free_slot == -1)
    free_slot = LroEvictFlow(batch, worker_flows);
  LroInitFlow(&worker_flows[free_slot], pkt, ip_offset, tcp_offset);
}

ADD_MODULE(LRO, "lro", "Aggregate multiple incoming packets from a single stream into a larger buffer")
