#include "tso.h"

void TSO::ProcessBatch(bess::PacketBatch *batch) {
  bess::PacketBatch new_batch_object = bess::PacketBatch();
  bess::PacketBatch *new_batch = &new_batch_object;
  new_batch->clear();

  int cnt = batch->cnt();
	
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    DoTso(new_batch, pkt);
  }
  RunNextModule(new_batch);
}	

void TSO::BatchPush(bess::PacketBatch *batch, bess::Packet *pkt) {
  batch->add(pkt);
  if (batch->full()) {
    RunNextModule(batch);
    batch->clear();
  }
}

void TSO::PushXpass(bess::Packet *pkt, Ipv4 *iph, uint16_t payload_offset) {
  uint8_t *head;

  if(unlikely((head = static_cast<uint8_t *>(pkt->prepend(XPASS_BYTES))) == nullptr)) {
    LOG(WARNING) << "[TSO Module] Failed to prepend packet.";
    return;
  }
  iph->length = be16_t(iph->length.value() + XPASS_BYTES);

  memmove(head, head + XPASS_BYTES, payload_offset);
}

void TSO::DoTso(bess::PacketBatch *new_batch, bess::Packet *pkt) {		
  uint16_t ip_offset;
  uint16_t tcp_offset;
  uint16_t payload_offset;
  uint32_t seq;

  int org_frame_len = pkt->total_len();
  int max_seg_size;
  int seg_size;

  // offset setting

  //get the headers of the packet
  Ethernet *eth = pkt->head_data<Ethernet *>();
  void *data = eth + 1;
	
  //[SKIP] check 802.1Q tag
  if (unlikely(eth->ether_type != be16_t(Ethernet::Type::kIpv4))) {
    BatchPush(new_batch, pkt);
    return;
  }

  Ipv4 *iph = reinterpret_cast<Ipv4 *>(data);
  size_t ip_bytes = (iph->header_length) << 2;

  if (unlikely(iph->protocol != Ipv4::Proto::kTcp)) {
    BatchPush(new_batch, pkt);
    return;
  }

  Tcp *tcph = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(iph) + ip_bytes);
  size_t tcp_bytes = (tcph->offset) << 2;

  data = reinterpret_cast<uint8_t *>(tcph) + tcp_bytes;

  ip_offset = reinterpret_cast<uint8_t *>(iph) - reinterpret_cast<uint8_t *>(eth);
  tcp_offset = reinterpret_cast<uint8_t *>(tcph) - reinterpret_cast<uint8_t *>(eth);
  payload_offset = reinterpret_cast<uint8_t *>(data) - reinterpret_cast<uint8_t *>(eth);

  if (org_frame_len <= FRAME_SIZE) {
    PushXpass(pkt, iph, payload_offset);
    BatchPush(new_batch, pkt);
    return;
  }

  seq = tcph->seq_num.value();
  max_seg_size = FRAME_SIZE - payload_offset;

  for (int i = payload_offset; i < org_frame_len; i += max_seg_size) {
    bess::Packet *new_pkt;

    uint16_t new_ip_total_len;

    bool first = (i == payload_offset);
    bool last = (i + max_seg_size >= org_frame_len);

    seg_size = std::min(org_frame_len - i, max_seg_size);

    new_pkt = bess::Packet::Alloc();
    // TODO: set head and tail of new packet
    // copy the headers
    bess::utils::Copy(new_pkt->append(payload_offset + XPASS_BYTES),
                      pkt->head_data(), payload_offset);

    eth = new_pkt->head_data<Ethernet *>();
    iph = new_pkt->head_data<Ipv4 *>(ip_offset);
    tcph = new_pkt->head_data<Tcp *>(tcp_offset);

    new_ip_total_len = (payload_offset - ip_offset) + seg_size + XPASS_BYTES;
    iph->length = be16_t(new_ip_total_len);
    tcph->seq_num = be32_t(seq);
    seq += seg_size;

    // CWR only for the first packet
    if (!first) {
      tcph->flags &= 0x7f;	
    }

    // PSH and FIN only for the last packet
    if (!last) {
      tcph->flags &= 0xf6;
    }

    bess::utils::Copy(new_pkt->append(seg_size), pkt->head_data(i), seg_size);
    BatchPush(new_batch, new_pkt);
  }
  bess::Packet::Free(pkt);
}

ADD_MODULE(TSO, "tso", "split large-sized TCP segments into small packets")
