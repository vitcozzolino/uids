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
#include <isotime>
#include <hw/nic.hpp>
#include <hw/devices.hpp>

void Service::start(const std::string& args)
{
#ifdef __GNUG__
  printf("Built by g++ " __VERSION__ "\n");
#endif
  printf("Hello world! Time is now %s\n", isotime::now().c_str());

  hw::Devices::print_devices();
  auto& eth0 = hw::Devices::nic(0);
  //auto current_ip4_upstream = eth0.ip4_upstream();
  eth0.set_ip4_upstream([](net::Packet_ptr pckt, const bool test){
      printf("IP4 Packet Capture function: size: %i bytes\n", pckt->size());
      for(size_t i=0; i<pckt->size(); i++) {
        if(i%40 == 0)
          printf("\n");
        printf("%02x", *(pckt->layer_begin()+i));
      }
      printf("\n");
    });
  eth0.set_arp_upstream([](net::Packet_ptr pckt){
      printf("full Packet Capture function: size: %i bytes\n", pckt->size());
    });
  eth0.set_ip6_upstream([](net::Packet_ptr pckt, const bool test){
      printf("IP6 Packet Capture function: size: %i bytes\n", pckt->size());
//      for(size_t i=0; i<pckt->size(); i++) {
//        if(i%8 == 0)
//          printf("\n");
//        printf("%02x ", *(pckt->layer_begin()+i));
//      }
      printf("\n");
    });
}
