/*
 * Sarah Tollman (stollman@stanford.edu)
 *   Modified by: Stephen Ibanez (sibanez@stanford.edu)
 */

#ifndef SIMPLE_SUME_SWITCH_H_
#define SIMPLE_SUME_SWITCH_H_

#include <bm/bm_sim/queue.h>
#include <bm/bm_sim/queueing.h>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/switch.h>
#include <bm/bm_sim/event_logger.h>
#include <bm/bm_sim/simple_pre_lag.h>

#include <memory>
#include <chrono>
#include <thread>
#include <vector>
#include <functional>

using ts_res = std::chrono::microseconds;
using std::chrono::duration_cast;
using ticks = std::chrono::nanoseconds;

using bm::Switch;
using bm::Queue;
using bm::Packet;
using bm::PHV;
using bm::Parser;
using bm::Deparser;
using bm::Pipeline;
using bm::Field;
using bm::FieldList;
using bm::packet_id_t;
using bm::p4object_id_t;
// TODO: remove unnecessary imports

// SUME ports are one-hot encoded
typedef uint8_t sume_port_t;
#define NF0_MASK 0x01
#define NF1_MASK 0x04
#define NF2_MASK 0x10
#define NF3_MASK 0x40
#define DMA0_MASK  0x02

#define DIGEST_SIZE 32

class SimpleSumeSwitch : public Switch {
 public:
  using TransmitFn = std::function<void(port_t, packet_id_t,
                                         const char *, int)>;

 public:
  // by default, swapping is off
  explicit SimpleSumeSwitch(port_t max_port = 5, bool enable_swap = false);

  ~SimpleSumeSwitch();

  int receive_(port_t port_num, const char *buffer, int len) override;

  void start_and_return_() override;

  void reset_target_state_() override;

  // returns the packet id of most recently received packet. Not thread-safe.
  static packet_id_t get_packet_id() {
    return (packet_id-1);
  }

  void set_transmit_fn(TransmitFn fn) {
    my_transmit_fn = std::move(fn);
  }

 private:
  static packet_id_t packet_id;
  TransmitFn my_transmit_fn;

};

#endif  // SIMPLE_SUME_SWITCH_H_
