/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *   Modified by: Sarah Tollman (stollman@stanford.edu)
 *   Modified by: Stephen Ibanez (sibanez@stanford.edu)
 */

#ifndef SIMPLE_SUME_SWITCH_H_
#define SIMPLE_SUME_SWITCH_H_

//TODO(sibanez): remove unnecessary include statements
#include <bm/bm_sim/queue.h>
//#include <bm/bm_sim/queueing.h>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/switch.h>
#include <bm/bm_sim/event_logger.h>

#include <memory>
#include <chrono>
#include <thread>
#include <vector>
#include <functional>
#include <map>

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

// SUME ports are one-hot encoded
typedef uint8_t sume_port_t;
#define PORT0_MASK 0x01
#define PORT1_MASK 0x04
#define PORT2_MASK 0x10
#define PORT3_MASK 0x40
#define DMA0_MASK  0x02

class SimpleSumeSwitch : public Switch {
 public:
  using TransmitFn = std::function<void(port_t, packet_id_t,
                                        const char *, int)>;

 private:
  using clock = std::chrono::high_resolution_clock;

 public:
  // by default, swapping is off
  // TODO(sibanez): set max_port correctly, one port will be used to receive pkts from the control-plane
  explicit SimpleSumeSwitch(port_t max_port = 5, bool enable_swap = false);

  ~SimpleSumeSwitch();

  int receive_(port_t port_num, const char *buffer, int len) override;

  void start_and_return_() override;

  // returns the packet id of most recently received packet. Not thread-safe.
  static packet_id_t get_packet_id() {
    return packet_id - 1;
  }

  void set_transmit_fn(TransmitFn fn);

 private:
  static packet_id_t packet_id;

 private:
  void transmit_thread();
  void ingress_thread();
  port_t lookup_egress_spec (sume_port_t dst_port);

 private:
  port_t max_port;
  std::vector<std::thread> threads_;
  Queue<std::unique_ptr<Packet> > input_buffer;
  Queue<std::unique_ptr<Packet> > output_buffer;
  TransmitFn my_transmit_fn;
  clock::time_point start;
  std::map<port_t, sume_port_t> port_map; 
};

#endif  // SIMPLE_SUME_SWITCH_H_
