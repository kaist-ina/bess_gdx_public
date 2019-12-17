#ifndef BESS_MODULE_XPASS_H_
#define BESS_MODULE_XPASS_H_

#include "../module.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/xpass.h"
#include "../utils/time.h"
#include "../utils/checksum.h"
#include <map>

#define IGATE_FROM_TX 0
#define IGATE_FROM_RX 1
#define IGATE_MAX 2

#define OGATE_TO_KERNEL 0
#define OGATE_TO_NIC 1
#define OGATE_MAX 2

#define CREDIT_SIZE 14+20+20+12
#define XPASS_IP_PROTO 146

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Xpass;
using bess::utils::Tcp;
using bess::utils::Vlan;
using bess::utils::be16_t;
using bess::utils::be32_t;

typedef enum XPASS_TCP_STATE_ {
  XPASS_TCP_CLOSED,
  XPASS_TCP_SYN_SENT,
  XPASS_TCP_SYN_RECEIVED,
  XPASS_TCP_SYNACK_SENT,
  XPASS_TCP_SYNACK_RECEIVED,
  XPASS_TCP_ESTABLISHED,
} XPASS_TCP_STATE;

typedef enum XPASS_SEND_STATE_ {
  XPASS_SEND_CLOSED,
  XPASS_SEND_CREDIT_SENDING,
  XPASS_SEND_CREDIT_STOP_RECEIVED,
  XPASS_SEND_NSTATE,
} XPASS_SEND_STATE;

typedef enum XPASS_RECV_STATE_ {
  XPASS_RECV_CLOSED,
  XPASS_RECV_CREDIT_REQUEST_SENT,
  XPASS_RECV_CREDIT_RECEIVING,
  XPASS_RECV_CREDIT_STOP_SENT,
  XPASS_RECV_NSTATE,
} XPASS_RECV_STATE;

struct list_elem {
  struct list_elem* prev;
  struct list_elem* next;
};

// Currently only support TCP.
typedef struct network_flow_key_ {
public:
  be32_t src_ip;
  be32_t dst_ip;
  be16_t src_port;
  be16_t dst_port;

  inline bool operator==(const network_flow_key_ &other) const {
    return (src_ip == other.src_ip) &&
           (dst_ip == other.dst_ip) &&
	   (src_port == other.src_port) &&
	   (dst_port == other.dst_port);
  }

  inline bool operator<(const network_flow_key_& other) const {
    return (src_ip < other.src_ip) ||
           (dst_ip < other.dst_ip) ||
	   (src_port < other.src_port) ||
	   (dst_port < other.dst_port);
  }

  inline std::ostream& operator<<(std::ostream& os) {
    os << bess::utils::ToIpv4Address(src_ip)
       << ":" << src_port.value()
       << " -> "
       << bess::utils::ToIpv4Address(dst_ip)
       << ":" << dst_port.value();
    return os;
  }

  inline void setForward(Ipv4 *iph, Tcp *tcph) {
    src_ip = iph->src;
    dst_ip = iph->dst;
    src_port = tcph->src_port;
    dst_port = tcph->dst_port;
  }

  inline void setReverse(Ipv4 *iph, Tcp *tcph) {
    src_ip = iph->dst;
    dst_ip = iph->src;
    src_port = tcph->dst_port;
    dst_port = tcph->src_port;
  }
} NetworkFlowKey;

typedef struct network_flow_{
  XPASS_SEND_STATE credit_send_state_;
  XPASS_RECV_STATE credit_recv_state_;
  XPASS_TCP_STATE tcp_state_;
  int max_credit_rate_;
  int cur_credit_rate_;
  double alpha_;
  double w_;

  list_elem tx_link;
  static const size_t kMaxCreditTemplateSize = 100;

  uint16_t credit_template_size_;
  unsigned char credit_template_[kMaxCreditTemplateSize];

  inline void Init() {
    credit_send_state_ = XPASS_SEND_CLOSED;
    credit_recv_state_ = XPASS_RECV_CLOSED;
    tcp_state_ = XPASS_TCP_CLOSED;
    max_credit_rate_ = 0;
    cur_credit_rate_ = 0;
    alpha_ = 0;
    w_ = 0;
    
    credit_template_size_ = 0;
    memset(credit_template_, 0, kMaxCreditTemplateSize);
    
    tx_link.prev = nullptr;
    tx_link.next = nullptr;
  }

  inline void SetSendState(XPASS_SEND_STATE new_state) {
    credit_send_state_ = new_state;
  }

  inline void SetRecvState(XPASS_RECV_STATE new_state) {
    credit_recv_state_ = new_state;
  }

  inline void SetTCPState(XPASS_TCP_STATE new_state) {
    tcp_state_ = new_state;
  }

  inline bool IsTxScheduled() {
    return (tx_link.prev || tx_link.next);
  }

  inline void SetCreditTemplate(char *c_temp, uint16_t size) {
    assert(size < kMaxCreditTemplateSize);
    credit_template_size_ = size;
    bess::utils::Copy(credit_template_, c_temp, size);
  }
} NetworkFlow;

class TimingWheel {
public:
  TimingWheel(): slots_() {}
  static const size_t kNumSlot = 2048;
  static const size_t kGranularity = 4000; // nano seconds.

  inline void Init(uint64_t clock) {
    front_local_ts_ = ConvertToLocalTS(clock);
  }

  inline void ScheduleFlow(NetworkFlow *flow, uint64_t clock) {
    assert(!flow->IsTxScheduled());
    uint64_t now = ConvertToLocalTS(clock);
    size_t idx;
    if (now <= front_local_ts_) {
      idx = currentIdx();
    }else if (now - front_local_ts_ < kNumSlot) {
      idx = now%kNumSlot;
    }else { // beyond the horizon.
      idx = (currentIdx()-1)%kNumSlot;
    }
    assert(idx < kNumSlot);
    if (slots_[idx].next) { // there exist element.
      assert(slots_[idx].prev);
      list_elem *head_elem = &slots_[idx];
      list_elem *last_elem = slots_[idx].prev;

      head_elem->prev = &flow->tx_link;
      last_elem->next = &flow->tx_link;

      flow->tx_link.next = head_elem;
      flow->tx_link.prev = last_elem;
    }else { // this is the first element.
      list_elem *head_elem = &slots_[idx];

      head_elem->prev = &flow->tx_link;
      head_elem->next = &flow->tx_link;

      flow->tx_link.next = head_elem;
      flow->tx_link.prev = head_elem;
    }
  }

  inline void ScheduleFlowNow(NetworkFlow *flow) {
    assert(!flow->IsTxScheduled());
    size_t idx = currentIdx();

    assert (idx < kNumSlot);
    if (slots_[idx].next) {
      assert(slots_[idx].next);
      list_elem *head_elem = &slots_[idx];
      list_elem *last_elem = slots_[idx].prev;

      head_elem->prev = &flow->tx_link;
      last_elem->next = &flow->tx_link;

      flow->tx_link.next = head_elem;
      flow->tx_link.prev = last_elem;
    }else {
      list_elem *head_elem = &slots_[idx];
      assert(!head_elem->prev && !head_elem->next);

      head_elem->prev = &flow->tx_link;
      head_elem->next = &flow->tx_link;

      flow->tx_link.next = head_elem;
      flow->tx_link.prev = head_elem;
    }
  }

  inline void DescheduleFlow(NetworkFlow *flow) {
    list_elem *elem_to_remove = &(flow->tx_link);

    if (!flow->IsTxScheduled()) {
      return;
    }

    assert(flow->IsTxScheduled());

    if (elem_to_remove->next == elem_to_remove->prev) {
      // last element in the list.
      list_elem *head_elem = elem_to_remove->prev;
      assert(head_elem->prev == head_elem->next);

      head_elem->next = nullptr;
      head_elem->prev = nullptr;
      elem_to_remove->next = nullptr;
      elem_to_remove->prev = nullptr;
    }else {
      elem_to_remove->next->prev = elem_to_remove->prev;
      elem_to_remove->prev->next = elem_to_remove->next;

      elem_to_remove->next = nullptr;
      elem_to_remove->prev = nullptr;
    }
  }

  inline void RescheduleFlow(NetworkFlow *flow, uint64_t clock) {
    DescheduleFlow(flow);
    ScheduleFlow(flow, clock);
  }

  inline void RescheduleFlowNow(NetworkFlow *flow) {
    DescheduleFlow(flow);
    ScheduleFlowNow(flow);
  }

  inline NetworkFlow *GetNextFlow(uint64_t clock) {
    uint64_t now = ConvertToLocalTS(clock);
    while (now >= front_local_ts_) {
      if (slots_[currentIdx()].next) { // while slot is not empty
        assert(slots_[currentIndx()].prev);
        list_elem *head_elem = &slots_[currentIdx()];
	list_elem *elem_to_remove = head_elem->next;
	if (head_elem->next == head_elem->prev) { // last element in the list.
	  assert(elem_to_remove->next == elem_to_remove->prev);

	  head_elem->next = nullptr;
	  head_elem->prev = nullptr;
	  elem_to_remove->next = nullptr;
	  elem_to_remove->prev = nullptr;
	}else { // still there are more element in the list.
	  elem_to_remove->next->prev = head_elem;
	  head_elem->next = elem_to_remove->next;

	  elem_to_remove->next = nullptr;
	  elem_to_remove->prev = nullptr;
	}
        return reinterpret_cast<NetworkFlow *>(
	    (char *)elem_to_remove - offsetof(NetworkFlow, tx_link));
      }else {
        assert(!slots_[currentIdx()].prev);
        front_local_ts_++;
      }
    }
    return nullptr;
  }

private:
  struct list_elem slots_[kNumSlot];
  uint64_t front_local_ts_;
  inline size_t currentIdx() {
    return (front_local_ts_%kNumSlot);
  }
  inline uint64_t ConvertToLocalTS(uint64_t wall_clock) {
    return (wall_clock/kGranularity);
  }
};

class TokenBucket {
public:
  TokenBucket(uint32_t rtime, uint64_t now) {
    token_ = 0;
    last_updated_time_ = now;
    refresh_time_ = rtime;
  }

  inline void updateToken(uint64_t now) {
    if (now <= last_updated_time_) {
      return;
    }

    uint32_t new_tokens = (now - last_updated_time_)/refresh_time_;
    if (new_tokens > 0) {
      token_ = std::min<uint32_t>(kMaxBurst, token_ + new_tokens);
      last_updated_time_ += new_tokens*refresh_time_;
    }
  }

  inline uint32_t getToken() {
    return token_;
  }

  inline void consumeToken(uint32_t token_used) {
    assert(token_used < token_);
    token_ -= token_used;
  }

  static const uint32_t kMaxBurst = CREDIT_SIZE * 8;
private:
  uint32_t token_; // in bytes
  uint64_t last_updated_time_; // in ns
  // the time to take to fill 1 bytes. (ns per bytes)
  // minimum rate = 1 bytes / 2^32 ns ~ 2bps
  // maximum rate = 1 bytes / 1 ns ~ 8Gbps
  uint32_t refresh_time_;
};

class XPassCore final : public Module {
public:
  XPassCore(): Module(){
    tx_timing_wheel.Init(now());
  }
  static const gate_idx_t kNumIGates = IGATE_MAX;
  static const gate_idx_t kNumOGates = OGATE_MAX;

  void ProcessBatch(bess::PacketBatch *batch);
private:
  // Helper functions
  void SetDSCP(Ipv4 *iph, int dscp);
  NetworkFlow* FindForwardFlow(Ipv4 *iph, Tcp *tcph);
  NetworkFlow* FindReverseFlow(Ipv4 *iph, Tcp *tcph);
  uint64_t now() {
    return tsc_to_ns(rdtsc());
  }

  // TX Path
  void ReceiveTx(bess::PacketBatch *batch);
  void ReceiveSynTx(NetworkFlow *flow);
  void ReceiveSynAckTx(NetworkFlow *flow);
  void ProcessAckTx(NetworkFlow *flow);

  // RX Path
  void ReceiveRx(bess::PacketBatch *batch);
  void ReceiveDataRx(NetworkFlow *flow, Ethernet *eth, Tcp *tcph);
  void ReceiveCreditRx();
  void ReceiveSynRx(NetworkFlow *flow, Ethernet *eth, Tcp *tcph);
  void ReceiveSynAckRx(NetworkFlow *flow);
  void ProcessAckRx(NetworkFlow *flow);

  std::map<NetworkFlowKey, NetworkFlow> flow_table; 
  TimingWheel tx_timing_wheel;
};

#endif  // BESS_MODULE_XPASS_H_
