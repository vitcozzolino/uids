// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015 Oslo and Akershus University College of Applied Sciences
// and Alfred Bratterud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <os>
#include <service>
#include "portscan_tcp_conntrack.hpp"
#include <hw/nic.hpp>
#include <net/interfaces.hpp>
#include <statman>
#include <timers>
#include <rtc>
#include <net/ip4/ip4.hpp>
#include <net/packet.hpp>
#include <net/ip4/packet_ip4.hpp>
#include <net/ip4/icmp4.hpp>
#include <net/ethernet/ethernet_8021q.hpp>
//#include <net/iana.hpp>

//received = Statman::get().get_by_name("eth0.ethernet.packets_rx").get_uint64();
#define TIMEOUT 5

using namespace net;

struct Entry {
  net::Socket source;
  RTC::timestamp_t timeout;
};

auto& eth0 = Interfaces::get_nic(0);

auto ct_obj = std::make_shared<PortscanConntrack>();

void icmp4_handler(std::unique_ptr<net::PacketIP4> packet){
  auto req = net::icmp4::Packet(std::move(packet));
  if(req.type() == ICMP_error::ICMP_type::DEST_UNREACHABLE && req.code() == (uint8_t) icmp4::code::Dest_unreachable::PORT)
  {
    auto payload = req.payload();
    auto header = *reinterpret_cast<ip4::Header*>(payload.data());
    uint16_t header_length = (header.version_ihl & 0xf) * 4;
    if(header_length+4 > payload.size()) { return; }
    uint16_t sport = (payload[header_length] << 8) + payload[header_length+1];
    uint16_t dport = (payload[header_length+2] << 8) + payload[header_length+3];
    Quadruple q = Quadruple({header.saddr, sport}, {header.daddr, dport});
    switch(static_cast<Protocol>(header.protocol)) {
      case Protocol::UDP:
        if(ct_obj->get(q, Protocol::UDP) != nullptr)
          ct_obj->handle_scan_packet(q, PortscanConntrack::PS_type::UDP_SCAN);
        break;
      default:
        break;
    } 
  } else {
    auto header = reinterpret_cast<net::PacketIP4*>(&req);
    ct_obj->in(*header);
  }
}
void ip4_capture(net::Packet_ptr pkt, [[maybe_unused]]const bool link_bcast)
{
  // Cast to IP4 Packet
  auto packet = static_unique_ptr_cast<net::PacketIP4>(std::move(pkt));

  // Do conntrack here custom function for tracking
  //PortscanConntrack::Entry_ptr ct = ct_obj->in(std::move(packet));
  // TODO port unreachable matching to UDP packets in conntrack table


  ct_obj->in(*packet);
//      for(size_t i=0; i<packet->size(); i++) {
//        if(i%8 == 0)
//          printf("\n");
//        printf("%02x ", *(packet->layer_begin()+i));}
  switch(packet->ip_protocol()) {
    case Protocol::TCP:
      //printf("FLAGS: %x\n", packet->ip_data()[13]); // <- works
      ct_obj->in(*packet);
      break;
    case Protocol::UDP:
      ct_obj->in(*packet);
      break;
    case Protocol::ICMPv4:
      icmp4_handler(std::move(packet));
      break;
    default:
      break;
  }

  //printf("<IP4 Receive> Source IP: %s Dest.IP: %s Type: %s LinkBcast: %d, Source Port: %d, Destination Port: %d\n",
  //       packet->ip_src().str().c_str(),
  //       packet->ip_dst().str().c_str(),
  //       str,
  //       link_bcast,
  //       src_port,
  //       dst_port
  //    );
  return;
}

void vlan_capture(net::Packet_ptr pkt) {
  auto& vlan = *reinterpret_cast<ethernet::VLAN_header*>(pkt->layer_begin());
  switch(vlan.type) {
    case Ethertype::IP4:
      pkt->increment_layer_begin(Ethernet_8021Q::header_size());
      ip4_capture(std::move(pkt), vlan.dest == MAC::BROADCAST);
      break;
    default:
      break;
  }
}

void Service::start(const std::string& args)
{
  eth0.set_ip4_upstream(ip4_capture);
  eth0.set_vlan_upstream(vlan_capture);
  ct_obj = std::make_shared<PortscanConntrack>();
  ct_obj->tcp_in = net::tcp::portscan_tcp4_conntrack;
	ct_obj->maximum_entries = 1000000;
	ct_obj->reserve(2000000);
  ct_obj->syn_flood_threshold = 1024;
  ct_obj->ack_flood_threshold = 1024; 
  ct_obj->udp_flood_threshold = 1024;
  ct_obj->icmp_flood_threshold = 1024;
  ct_obj->flood_interval = std::chrono::seconds{1};
  ct_obj->flush_interval = std::chrono::seconds{5};
	//ct_obj->timeout.established.tcp = Conntrack::Timeout_duration{ 100 };
	//ct_obj->timeout.established.udp = Conntrack::Timeout_duration{ 200 };
	//ct_obj->timeout.established.icmp = Conntrack::Timeout_duration{ 300 };
	//ct_obj->timeout.confirmed.tcp = Conntrack::Timeout_duration{ 700 };
	//ct_obj->timeout.confirmed.udp = Conntrack::Timeout_duration{ 800 };
	//ct_obj->timeout.confirmed.icmp = Conntrack::Timeout_duration{ 900 };
	//ct_obj->timeout.unconfirmed.tcp = Conntrack::Timeout_duration{ 4 };
	//ct_obj->timeout.unconfirmed.udp = Conntrack::Timeout_duration{ 500 };
	//ct_obj->timeout.unconfirmed.icmp = Conntrack::Timeout_duration{ 600 };

}
