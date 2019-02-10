/*
 * Sarah Tollman (stollman@stanford.edu)
 *   Modified by: Stephen Ibanez (sibanez@stanford.edu)
 */

#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/tables.h>
#include <bm/bm_sim/logger.h>

#include <bm/bm_runtime/bm_runtime.h>

#include <unistd.h>

#include <iostream>
#include <fstream>
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

//extern int import_primitives();

using bm::ByteContainer;

packet_id_t SimpleSumeSwitch::packet_id = 0;

SimpleSumeSwitch::SimpleSumeSwitch(port_t max_port, bool enable_swap)
  : Switch(enable_swap),
    max_port(max_port),
    my_transmit_fn([this](port_t port_num, packet_id_t pkt_id,
                        const char *buffer, int len) {
      _BM_UNUSED(pkt_id);
      this->transmit_fn(port_num, buffer, len);
  }) {

  // Initialize the port_map
  port_map[1] = DMA0_MASK;
  port_map[2] = NF0_MASK;
  port_map[3] = NF1_MASK;
  port_map[4] = NF2_MASK;
  port_map[5] = NF3_MASK;

  add_required_field("sume_metadata_t", "dma_q_size");
  add_required_field("sume_metadata_t", "nf3_q_size");
  add_required_field("sume_metadata_t", "nf2_q_size");
  add_required_field("sume_metadata_t", "nf1_q_size");
  add_required_field("sume_metadata_t", "nf0_q_size");
  add_required_field("sume_metadata_t", "send_dig_to_cpu");
  add_required_field("sume_metadata_t", "dst_port");
  add_required_field("sume_metadata_t", "src_port");
  add_required_field("sume_metadata_t", "pkt_len");

  force_arith_header("sume_metadata_t");
  force_arith_header("user_metadata_t");
  force_arith_header("digest_data_t");

//  import_primitives();
}

SimpleSumeSwitch::~SimpleSumeSwitch() {}

#define PACKET_LENGTH_REG_IDX 0

int
SimpleSumeSwitch::receive_(port_t port_num, const char *buffer, int len) {
  if (port_num > max_port) {
      bm::Logger::get()->error("Packet arrived on invalid port %u, dropping packet", port_num);
      return 0;
  }
  // we limit the packet buffer to original size + 512 bytes, which means we
  // cannot add more than 512 bytes of header data to the packet, which should
  // be more than enough

// https://github.com/p4lang/behavioral-model/blob/b826576c0d85c23ff9d59571fb70e44dc8475905/src/bm_sim/switch.cpp#L509
  auto packet = new_packet_ptr(port_num, packet_id++, len,
                               bm::PacketBuffer(len + 512, buffer, len));

  BMELOG(packet_in, *packet); // TODO: what is packet_in?

  PHV *phv = packet->get_phv();
  // many current P4 programs assume this
  // it is also part of the original P4 spec
  phv->reset_metadata();

  // TODO(sibanez): set queue size metadata fields

  sume_port_t src_port = port_map[port_num];
  phv->get_field("sume_metadata_t.src_port").set(src_port);

  // using packet register 0 to store length, this register will be updated for
  // each add_header / remove_header primitive call
  packet->set_register(PACKET_LENGTH_REG_IDX, len);
  phv->get_field("sume_metadata_t.pkt_len").set(len);

  Parser *parser = this->get_parser("parser");
  Pipeline *pipeline = this->get_pipeline("TopPipe");
  Deparser *deparser = this->get_deparser("deparser");

  port_t ingress_port = packet->get_ingress_port();
  (void) ingress_port;
  BMLOG_DEBUG_PKT(*packet, "Processing packet received on port {}",
                  ingress_port);

  parser->parse(packet.get());
  pipeline->apply(packet.get());
  packet->reset_exit(); // TODO: do I need this?
  deparser->deparse(packet.get());

  sume_port_t dst_port = phv->get_field("sume_metadata_t.dst_port").get_uint();
  if (dst_port == 0) {
    // drop packet
    BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of ingress");
    // TODO: technically still need to send digest_data to control-plane
    // if the send_dig_to_cpu field is set
    return 0;
  }

  // TODO: add support for broadcasting
  port_t egress_spec;
  if (dst_port & DMA0_MASK)
    egress_spec = 1;
  if (dst_port & NF0_MASK)
    egress_spec = 2;
  if (dst_port & NF1_MASK)
    egress_spec = 3;
  if (dst_port & NF2_MASK)
    egress_spec = 4;
  if (dst_port & NF3_MASK)
    egress_spec = 5;

  packet->set_egress_port(egress_spec);
  BMLOG_DEBUG_PKT(*packet, "Packet destined for port {} at end of ingress", egress_spec);

  bool send_dig_to_cpu = (phv->get_field("sume_metadata_t.send_dig_to_cpu").get_uint() != 0);
  if ((dst_port & DMA0_MASK) && send_dig_to_cpu) {
    //TODO(sibanez): prepend digest_data to packet before transmission
    ByteContainer digest_data(DIGEST_SIZE);
    const ByteContainer dig_src_port = phv->get_field("scalars.digest_data_t.src_port").get_bytes();
    const ByteContainer dig_code = phv->get_field("scalars.digest_data_t.digest_code").get_bytes();
    digest_data.append(dig_src_port);
    digest_data.append(dig_code);
    BMLOG_DEBUG("Created digest_data (" + std::to_string(digest_data.size()) +"B): " + digest_data.to_hex());
    // TODO(sibanez): check digest_data
    ByteContainer new_packet(packet->data(), packet->get_data_size());
    new_packet.insert(new_packet.begin(), digest_data);
    // replace packet with digest_data ++ packet
//    memcpy(packet->data(), new_packet.data(), new_packet.size());
  }

  // TODO: send digest_data to control-plane if send_dig_to_cpu field is set (even if the the packet is not forwarded to the control-plane)

  BMELOG(packet_out, *packet);
  BMLOG_DEBUG_PKT(*packet, "Transmitting packet of size {} out of port {}",
                  packet->get_data_size(), packet->get_egress_port());

  my_transmit_fn(packet->get_egress_port(), packet->get_packet_id(),
                 packet->data(), packet->get_data_size());

  return 0;
}

void
SimpleSumeSwitch::start_and_return_() { }

void
SimpleSumeSwitch::reset_target_state_() {
  bm::Logger::get()->debug("Resetting simple_sume_switch target-specific state");
}

