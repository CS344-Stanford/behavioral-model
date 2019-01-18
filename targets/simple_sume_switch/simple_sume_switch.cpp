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
 *
 */

#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/tables.h>
#include <bm/bm_sim/logger.h>

#include <unistd.h>

#include <iostream>
#include <fstream>
#include <mutex>
#include <string>

#include "simple_sume_switch.h"

namespace {

struct hash_ex {
  uint32_t operator()(const char *buf, size_t s) const {
    const uint32_t p = 16777619;
    uint32_t hash = 2166136261;

    for (size_t i = 0; i < s; i++)
      hash = (hash ^ buf[i]) * p;

    hash += hash << 13;
    hash ^= hash >> 7;
    hash += hash << 3;
    hash ^= hash >> 17;
    hash += hash << 5;
    return static_cast<uint32_t>(hash);
  }
};

struct bmv2_hash {
  uint64_t operator()(const char *buf, size_t s) const {
    return bm::hash::xxh64(buf, s);
  }
};

}  // namespace

// if REGISTER_HASH calls placed in the anonymous namespace, some compiler can
// give an unused variable warning
REGISTER_HASH(hash_ex);
REGISTER_HASH(bmv2_hash);

extern int import_primitives();

packet_id_t SimpleSumeSwitch::packet_id = 0;

SimpleSumeSwitch::SimpleSumeSwitch(port_t max_port, bool enable_swap)
  : Switch(enable_swap),
    max_port(max_port),
    input_buffer(1024),
    output_buffer(128),
    // cannot use std::bind because of a clang bug
    // https://stackoverflow.com/questions/32030141/is-this-incorrect-use-of-stdbind-or-a-compiler-bug
    my_transmit_fn([this](port_t port_num, packet_id_t pkt_id,
                          const char *buffer, int len) {
        _BM_UNUSED(pkt_id);
        this->transmit_fn(port_num, buffer, len);
    }),
    start(clock::now()) {

  // Initialize the port_map
  port_map[0] = 0x01;
  port_map[1] = 0x04;
  port_map[2] = 0x10;
  port_map[3] = 0x40;
  port_map[4] = 0x02;

  // TODO(sibanez): do these need to be called standard_metadata if we want to reuse the simple_switch compiler backend, or can we use @alias in the architecture definition?
  add_required_field("sume_metadata", "dma_q_size");
  add_required_field("sume_metadata", "nf3_q_size");
  add_required_field("sume_metadata", "nf2_q_size");
  add_required_field("sume_metadata", "nf1_q_size");
  add_required_field("sume_metadata", "nf0_q_size");
  add_required_field("sume_metadata", "send_dig_to_cpu");
  add_required_field("sume_metadata", "dst_port");
  add_required_field("sume_metadata", "src_port");
  add_required_field("sume_metadata", "pkt_len");

  force_arith_header("sume_metadata");
  force_arith_header("user_metadata");
  force_arith_header("digest_data");

  import_primitives();
}

#define PACKET_LENGTH_REG_IDX 0

int
SimpleSumeSwitch::receive_(port_t port_num, const char *buffer, int len) {
  // we limit the packet buffer to original size + 512 bytes, which means we
  // cannot add more than 512 bytes of header data to the packet, which should
  // be more than enough
  auto packet = new_packet_ptr(port_num, packet_id++, len,
                               bm::PacketBuffer(len + 512, buffer, len));

  BMELOG(packet_in, *packet);

  PHV *phv = packet->get_phv();
  // many current P4 programs assume this
  // it is also part of the original P4 spec
  phv->reset_metadata();

  // setting standard metadata

  // TODO(sibanez): set queue size metadata fields

  sume_port_t src_port = port_map[port_num];
  phv->get_field("sume_metadata.src_port").set(src_port);
  // using packet register 0 to store length, this register will be updated for
  // each add_header / remove_header primitive call
  packet->set_register(PACKET_LENGTH_REG_IDX, len);
  phv->get_field("sume_metadata.pkt_len").set(len);

  input_buffer.push_front(std::move(packet));
  return 0;
}

void
SimpleSumeSwitch::start_and_return_() {
  threads_.push_back(std::thread(&SimpleSwitch::ingress_thread, this));
  threads_.push_back(std::thread(&SimpleSwitch::transmit_thread, this));
}

SimpleSumeSwitch::~SimpleSumeSwitch() {
  input_buffer.push_front(nullptr);
  output_buffer.push_front(nullptr);
  for (auto& thread_ : threads_) {
    thread_.join();
  }
}

void
SimpleSumeSwitch::set_transmit_fn(TransmitFn fn) {
  my_transmit_fn = std::move(fn);
}

void
SimpleSwitch::transmit_thread() {
  while (1) {
    std::unique_ptr<Packet> packet;
    output_buffer.pop_back(&packet);
    if (packet == nullptr) break;
    BMELOG(packet_out, *packet);
    BMLOG_DEBUG_PKT(*packet, "Transmitting packet of size {} out of port {}",
                    packet->get_data_size(), packet->get_egress_port());
    my_transmit_fn(packet->get_egress_port(), packet->get_packet_id(),
                   packet->data(), packet->get_data_size());
  }
}

void
SimpleSumeSwitch::ingress_thread() {
  PHV *phv;

  while (1) {
    std::unique_ptr<Packet> packet;
    input_buffer.pop_back(&packet);
    if (packet == nullptr) break;

    Parser *parser = this->get_parser("parser");
    Pipeline *ingress_mau = this->get_pipeline("ingress");
    Deparser *deparser = this->get_deparser("deparser");

    phv = packet->get_phv();

    port_t ingress_port = packet->get_ingress_port();
//    (void) ingress_port;
    BMLOG_DEBUG_PKT(*packet, "Processing packet received on port {}",
                    ingress_port);

    parser->parse(packet.get());
    ingress_mau->apply(packet.get());
    packet->reset_exit();
    deparser->deparse(packet.get());

    sume_port_t dst_port = phv->get_field("sume_metadata.dst_port").get_uint();
    if (dst_port == 0) {
      // drop packet
      BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of ingress");
      continue;
    }
    else {
      //TODO(sibanez): add support for broadcasting
      port_t egress_spec = lookup_egress_spec(dst_port);
      packet->set_egress_port(egress_spec);
      BMLOG_DEBUG_PKT(*packet, "Packet destined for port {} at end of ingress", egress_spec);

      bool send_dig_to_cpu = phv->get_field("sume_metadata.send_dig_to_cpu").get_bool();
      if ((dst_port & DMA0_MASK) && send_dig_to_cpu) {
        //TODO(sibanez): prepend digest_data to packet before transmission
      }

      output_buffer.push_front(std::move(packet));
    }
  }
}

port_t
SimpleSumeSwitch::lookup_egress_spec(sume_port_t dst_port) {
  if (dst_port & PORT0_MASK)
    return 0;
  if (dst_port & PORT1_MASK)
    return 1;
  if (dst_port & PORT2_MASK)
    return 2;
  if (dst_port & PORT3_MASK)
    return 3;
  if (dst_port & DMA0_MASK)
    return 4;
  return 0; // default (should never happen)
}

}
