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

#include <service>
#include <hw/nic.hpp>
#include <hw/devices.hpp>
#include <statman>
#include <timers>
#include <rtc>
#include <net/ip4/ip4.hpp>
#include <net/packet.hpp>
#include <net/ip4/packet_ip4.hpp>
//#include <net/iana.hpp>

//received = Statman::get().get_by_name("eth0.ethernet.packets_rx").get_uint64();

using namespace net;

static uint64_t received = 0;
static uint64_t ts = 0;
static uint64_t ts_new = 0;
auto& eth0 = hw::Devices::nic(0);

void print_packets()
{
  ts_new = RTC::nanos_now();
  uint64_t diff = ts_new-ts;
  ts = ts_new;
  uint64_t tmp = eth0.get_packets_rx();
  printf("Received %d packets in %f seconds\n", tmp-received, (double) diff/1000000000UL);
  received=tmp;
}

void ip4_capture(net::Packet_ptr pkt, const bool link_bcast)
{
  // Cast to IP4 Packet
  auto packet = static_unique_ptr_cast<net::PacketIP4>(std::move(pkt));

  auto l = packet->ip_header_length();
  auto str = "";
  switch(packet->ip_protocol()) {
    case Protocol::TCP:
      str = "TCP";
      break;
    case Protocol::UDP:
      str = "UDP";
      break;
    default:
      str = "Other";
  }
  printf("<IP4 Receive> Source IP: %s Dest.IP: %s Type: %s LinkBcast: %d, Source Port: %d, Destination Port: %d\n",
         packet->ip_src().str().c_str(),
         packet->ip_dst().str().c_str(),
         str,
         link_bcast,
         ntohs(*(uint16_t*)(packet->layer_begin()+l)),
         ntohs(*(uint16_t*)(packet->layer_begin()+l+2))
      );
  for(uint8_t i = 0; i<l+4; i++) {
    //printf("%02x", *(packet->layer_begin()+i));
  }
  //printf("\n");
}

void Service::start(const std::string& args)
{
  hw::Devices::print_devices();
  eth0.set_ip4_upstream(ip4_capture);
  Timers::periodic(std::chrono::seconds(1), std::chrono::seconds(1), [] (uint32_t) {
      print_packets();
  });
}
