#include "xpass_core.h"

// Helper function implementations
void XPassCore::SetDSCP(Ipv4 *iph, int dscp) {
  if (dscp < 0 || dscp > 127) {
    LOG(INFO) << "[XPass Core] Tried to set invalid DSCP value";
    return;
  }

  iph->type_of_service = (dscp << 2) | (iph->type_of_service & 0x3);
}

NetworkFlow* XPassCore::FindForwardFlow(Ipv4 *iph, Tcp *tcph) {
  NetworkFlowKey nfk;
  nfk.src_ip = iph->src;
  nfk.dst_ip = iph->dst;
  nfk.src_port = tcph->src_port;
  nfk.dst_port = tcph->dst_port; 

  std::map<NetworkFlowKey, NetworkFlow>::iterator it;
  it = flow_table.find(nfk);

  if(it != flow_table.end()) {
    return &(it->second);
  }

  return nullptr;
}

NetworkFlow* XPassCore::FindReverseFlow(Ipv4 *iph, Tcp *tcph) {
  NetworkFlowKey nfk;
  nfk.src_ip = iph->dst;
  nfk.dst_ip = iph->src;
  nfk.src_port = tcph->dst_port;
  nfk.dst_port = tcph->src_port; 

  std::map<NetworkFlowKey, NetworkFlow>::iterator it;
  it = flow_table.find(nfk);

  if(it != flow_table.end()) {
    return &(it->second);
  }

  return nullptr;
}

void XPassCore::ProcessBatch(bess::PacketBatch *batch) {
  gate_idx_t incoming_gate = get_igate();

  switch (incoming_gate) {
    case IGATE_FROM_TX:
      ReceiveTx(batch);
      break;
    case IGATE_FROM_RX:
      ReceiveRx(batch);
      break;
    default:
      LOG(ERROR) << "[XpassCore] Invalid input gate.";
  }
}

// TX Path implementations
void XPassCore::ReceiveTx(bess::PacketBatch *batch) {
  bess::PacketBatch new_batch;
  int cnt = batch->cnt();

  new_batch.clear();

  for (int i=0; i<cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    
    Ethernet *eth = pkt->head_data<Ethernet *>();
    void *data = eth + 1;
    be16_t ether_type = eth->ether_type;

    if (ether_type == be16_t(Ethernet::Type::kQinQ)) {
      Vlan *qinq = reinterpret_cast<Vlan *>(data);
      data = qinq + 1;
      ether_type = qinq->ether_type;
      if (ether_type != be16_t(Ethernet::Type::kVlan)) {
        LOG(WARNING) << "[Fatal Error] ExpressPass Core detected wrong packet. (Vlan)";
      }
    }

    if (ether_type == be16_t(Ethernet::Type::kVlan)) {
      Vlan *vlan = reinterpret_cast<Vlan *>(data);
      data = vlan + 1;
      ether_type = vlan->ether_type;
    }

    if (ether_type != be16_t(Ethernet::Type::kIpv4)) {
      // not IP packet.
      new_batch.add(pkt);
      continue;
    }

    Ipv4 *iph = reinterpret_cast<Ipv4 *>(data);

    if (iph->protocol != Ipv4::Proto::kTcp) {
      // not TCP packet.
      new_batch.add(pkt);
      continue;
    }

    size_t ip_bytes = (iph->header_length) << 2;
    Tcp *tcph =
        reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(iph) + ip_bytes);

    size_t tcp_bytes = (tcph->offset) << 2;
    // now data points to the payload.
    data = reinterpret_cast<uint8_t *>(tcph) + tcp_bytes;

    NetworkFlow *flow = FindForwardFlow(iph, tcph);
    if (!flow) {
      NetworkFlowKey new_key;
      NetworkFlow new_flow;

      new_key.setForward(iph, tcph);

      flow_table.insert(std::pair<NetworkFlowKey, NetworkFlow>(new_key, new_flow));
      flow = &new_flow;
      flow->Init();
    }

//    Xpass *xph =
//          reinterpret_cast<Xpass *>(reinterpret_cast<uint8_t *>(data) - sizeof(Xpass));

//    xph->packet_type = 1;
//    xph->credit_seq_num = 2;
//    xph->time = 3;

    // Handle SYN/SYNACK
    if ((tcph->flags & Tcp::Flag::kSyn) && !(tcph->flags & Tcp::Flag::kAck)) {
      ReceiveSynTx(flow);
    } else if ((tcph->flags & Tcp::Flag::kSyn) && (tcph->flags & Tcp::Flag::kAck)) {
      ReceiveSynAckTx(flow);
    }

    SetDSCP(iph, 1);
    // Recalculate checksum
    iph->checksum = CalculateIpv4Checksum(*iph);
    tcph->checksum = CalculateIpv4TcpChecksum(*iph, *tcph);
    
    // Handle ACK
    if (tcph->flags & Tcp::Flag::kAck) {
      ProcessAckTx(flow);
    }
    
    new_batch.add(pkt);
  }

  RunChooseModule(OGATE_TO_NIC, &new_batch);
}

void XPassCore::ReceiveSynTx(NetworkFlow *flow) {
  // Got Syn from TX module
  // 1. Init flow. (state = CLOSED)
  flow->Init();

  // 2. store credit template
  /*
  void *data = tcph + 1;
  Xpass *xpassh = reinterpret_cast<Xpass *>(data);

  data = xpassh + 1;

  flow->SetCreditTemplate((char *)eth, (char *)data - (char *)eth);
  */

  // 4. change TCP state
  flow->SetTCPState(XPASS_TCP_SYN_SENT);
}

void XPassCore::ReceiveSynAckTx(NetworkFlow *flow) {
  if (flow->tcp_state_ == XPASS_TCP_SYN_RECEIVED) {
    flow->SetTCPState(XPASS_TCP_SYNACK_SENT);
  }
}

void XPassCore::ProcessAckTx(NetworkFlow *flow) {
  if (flow->tcp_state_ == XPASS_TCP_SYNACK_RECEIVED) {
    flow->SetTCPState(XPASS_TCP_ESTABLISHED);
    LOG(INFO) << "Connection Established!";
  }
}

// RX Path implementations
void XPassCore::ReceiveRx(bess::PacketBatch *batch) {
  bess::PacketBatch new_batch;
  int cnt = batch->cnt();

  new_batch.clear();

  for (int i=0; i<cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    
    Ethernet *eth = pkt->head_data<Ethernet *>();
    void *data = eth + 1;
    be16_t ether_type = eth->ether_type;

    if (ether_type == be16_t(Ethernet::Type::kQinQ)) {
      Vlan *qinq = reinterpret_cast<Vlan *>(data);
      data = qinq + 1;
      ether_type = qinq->ether_type;
      if (ether_type != be16_t(Ethernet::Type::kVlan)) {
        LOG(WARNING) << "[Fatal Error] ExpressPass Core detected wrong packet. (Vlan)";
      }
    }

    if (ether_type == be16_t(Ethernet::Type::kVlan)) {
      Vlan *vlan = reinterpret_cast<Vlan *>(data);
      data = vlan + 1;
      ether_type = vlan->ether_type;
    }

    if (ether_type != be16_t(Ethernet::Type::kIpv4)) {
      new_batch.add(pkt);
      continue;
    }

    Ipv4 *iph = reinterpret_cast<Ipv4 *>(data);

    if (iph->protocol != Ipv4::Proto::kTcp) {
      new_batch.add(pkt);
      continue;
    }
    uint8_t dscp = (iph->type_of_service >> 2);
    size_t ip_bytes = (iph->header_length) << 2;

    Tcp *tcph =
        reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(iph) + ip_bytes);
    data = tcph + 1;

    Xpass *xph = reinterpret_cast<Xpass *>(data);
    data = xph + 1;

    NetworkFlow *flow = FindReverseFlow(iph, tcph);
    if (!flow) {
      NetworkFlowKey new_key;
      NetworkFlow new_flow;

      new_key.setReverse(iph, tcph);

      flow_table.insert(std::pair<NetworkFlowKey, NetworkFlow>(new_key, new_flow));
      flow = &new_flow;
      flow->Init();
    }

    if (dscp == 2) {
      // credit packets.
      ReceiveCreditRx();
      continue;
    }

    if (dscp == 1) {
      ReceiveDataRx(flow, eth, tcph);
    }
    new_batch.add(pkt);

    if (tcph->flags & Tcp::Flag::kAck) {
      ProcessAckRx(flow);
    }
  }
  RunChooseModule(OGATE_TO_KERNEL, &new_batch);
}

void XPassCore::ReceiveDataRx(NetworkFlow *flow, Ethernet *eth, Tcp *tcph) {
  if ((tcph->flags & Tcp::Flag::kSyn) && !(tcph->flags & Tcp::Flag::kAck)) {
    ReceiveSynRx(flow, eth, tcph);
  } else if ((tcph->flags & Tcp::Flag::kSyn) && (tcph->flags & Tcp::Flag::kAck)) {
    ReceiveSynAckRx(flow);
  }
}

void XPassCore::ReceiveCreditRx() {

}

void XPassCore::ReceiveSynRx(NetworkFlow *flow, Ethernet *eth, Tcp *tcph) {
  // Got Syn from RX path
  // Init flow.
  flow->Init();

  // 2. store credit template
  void *data = tcph + 1;
  Xpass *xph = reinterpret_cast<Xpass *>(data);
  data = xph + 1;
  flow->SetCreditTemplate((char *)eth, (char *)data - (char *)eth);

  // 3. change TCP state
  flow->SetTCPState(XPASS_TCP_SYN_RECEIVED);
}

void XPassCore::ReceiveSynAckRx(NetworkFlow *flow) {
  if (flow->tcp_state_ == XPASS_TCP_SYN_SENT) {
    flow->SetTCPState(XPASS_TCP_SYNACK_RECEIVED);
  }
}

void XPassCore::ProcessAckRx(NetworkFlow *flow) {
  if(flow->tcp_state_ == XPASS_TCP_SYNACK_SENT) {
    flow->SetTCPState(XPASS_TCP_ESTABLISHED);
    LOG(INFO) << "Connection Established!";
  }
}

ADD_MODULE(XPassCore, "xpass-core", "ExpressPass core module")
