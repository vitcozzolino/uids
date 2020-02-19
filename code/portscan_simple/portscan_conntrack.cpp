// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2017 Oslo and Akershus University College of Applied Sciences
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

#include "portscan_tcp_conntrack.hpp"
#include "portscan_conntrack.hpp"
#include <sstream>
#include <set>
#include <statman>

#define PORT_TIMEOUT 1200
#define SCANNED_TIMEOUT 30
#define HOSTSHIT_TIMEOUT 30
#define PORTSHIT_TIMEOUT 30
#define TIMEOUT 30
#define THRESHOLD_PORTSHIT 5
#define THRESHOLD_HOSTSHIT 5
//#define CT_DEBUG 1
#ifdef CT_DEBUG
#define CTDBG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define CTDBG(fmt, ...) /* fmt */
#endif

namespace net {

std::string myproto_str(const Protocol proto)
{
  switch(proto) {
    case Protocol::TCP: return "TCP";
    case Protocol::UDP: return "UDP";
    case Protocol::ICMPv4: return "ICMPv4";
    default: return "???";
  }
}

std::string state_str(const PortscanConntrack::State state)
{
  switch(state) {
    case PortscanConntrack::State::NEW: return "NEW";
    case PortscanConntrack::State::ESTABLISHED: return "EST";
    case PortscanConntrack::State::RELATED: return "RELATED";
    case PortscanConntrack::State::UNCONFIRMED: return "UNCONFIRMED";
    default: return "???";
  }
}

std::string myflag_str(const uint8_t flags)
{
  std::string str;
  if(flags & static_cast<uint8_t>(PortscanConntrack::Flag::UNREPLIED))
    str.append(" UNREPLIED");
  if(flags & static_cast<uint8_t>(PortscanConntrack::Flag::ASSURED))
    str.append(" ASSURED");
  return str;
}

std::string PortscanConntrack::ps_type_str(const PortscanConntrack::PS_type ps_type) const
{
  switch(ps_type) {
    case PortscanConntrack::PS_type::SYN_NOREPLY: return "SYN_NOREPLY";
    case PortscanConntrack::PS_type::SYN_CLOSED: return "SYN_CLOSED";
    case PortscanConntrack::PS_type::SYN_OPEN: return "SYN_OPEN";
    case PortscanConntrack::PS_type::XMAS_SCAN: return "XMAS_SCAN";
    case PortscanConntrack::PS_type::FIN_SCAN: return "FIN_SCAN";
    case PortscanConntrack::PS_type::NULL_SCAN: return "NULL_SCAN";
    case PortscanConntrack::PS_type::UDP_SCAN: return "UDP_SCAN";
    case PortscanConntrack::PS_type::SYN_FLOOD: return "SYN_FLOOD";
    case PortscanConntrack::PS_type::ACK_FLOOD: return "ACK_FLOOD";
    case PortscanConntrack::PS_type::UDP_FLOOD: return "UDP_FLOOD";
    case PortscanConntrack::PS_type::ICMP_FLOOD: return "ICMP_FLOOD";
    default: return "???";
  }
}

std::string PortscanConntrack::Entry::to_string() const
{
  return "[ " + first.to_string() + " ] [ " + second.to_string() + " ]"
    + " P: " + myproto_str(proto) + " S: " + state_str(state) + " F:" + myflag_str(flags);
}

PortscanConntrack::Entry::~Entry()
{
  if(this->on_close)
    on_close(this);
}

PortscanConntrack::Entry* PortscanConntrack::simple_track_in(Quadruple q, const Protocol proto)
{
  switch(proto){
    case Protocol::UDP:
      handle_flood_packet(q, PS_type::UDP_FLOOD);
      break;
    case Protocol::ICMPv4:
      handle_flood_packet(q, PS_type::ICMP_FLOOD);
      break;
    default:
      break;
  }
  // find the entry
  auto* entry = get(q, proto);

  CTDBG("<PortscanConntrack> Track in S: %s - D: %s\n",
    q.src.to_string().c_str(), q.dst.to_string().c_str());

  // if none, add new and return
  if(entry == nullptr)
  {
    entry = add_entry(q, proto);
    return entry;
  }

  // temp
  CTDBG("<PortscanConntrack> Entry found: %s\n", entry->to_string().c_str());

  if(entry->state == State::NEW and q == entry->second)
  {
    entry->state = State::ESTABLISHED;
    CTDBG("<PortscanConntrack> Assuming ESTABLISHED\n");
  }

  update_timeout(*entry, (entry->state == State::ESTABLISHED) ? timeout.established : timeout.confirmed);

  return entry;
}

PortscanConntrack::Entry* dumb_in(PortscanConntrack& ct, Quadruple q, const PacketIP4& pkt)
{ return  ct.simple_track_in(std::move(q), pkt.ip_protocol()); }

PortscanConntrack::PortscanConntrack()
 : PortscanConntrack(0)
{}

PortscanConntrack::PortscanConntrack(size_t max_entries)
 : maximum_entries{max_entries},
   tcp_in{&dumb_in},
   flush_timer({this, &PortscanConntrack::on_timeout}),
   flood_timer({this, &PortscanConntrack::on_flood_timeout})
{
}

PortscanConntrack::Entry* PortscanConntrack::get(const PacketIP4& pkt) const
{
  const auto proto = pkt.ip_protocol();
  switch(proto)
  {
    case Protocol::TCP:
    case Protocol::UDP:
      return get(get_quadruple(pkt), proto);

    case Protocol::ICMPv4:
      return get(get_quadruple_icmp(pkt), proto);

    default:
      return nullptr;
  }
}

PortscanConntrack::Entry* PortscanConntrack::get(const Quadruple& quad, const Protocol proto) const
{
  auto it = entries.find({quad, proto});

  if(it != entries.end())
    return it->second.get();

  return nullptr;
}

bool PortscanConntrack::isopen(const Socket s) const
{
  auto it = open_ports.find(s);

  if(it != open_ports.end())
    return true;

  return false;
}

bool PortscanConntrack::add_open_port(const Socket s)
{
  open_ports[s] = RTC::nanos_now()/1000000000ull+PORT_TIMEOUT;
  return true;
}

void PortscanConntrack::handle_flood_packet(const Quadruple& quad, const PS_type ps_type)
{
  auto* f_ent = get_flood_entry(quad.dst, ps_type);
  auto it = f_ent->source.find(quad.src.address());
  if(it != f_ent->source.end())
  {
    it->second.ctr++;
    it->second.type = ps_type;
  }
  else
    f_ent->source[quad.src.address()] = {1, ps_type};
}

void PortscanConntrack::handle_scan_packet(const Quadruple& quad, const PS_type ps_type)
{
  if(not flush_timer.is_running())
    flush_timer.start(flush_interval);
  const auto NOW = RTC::nanos_now()/1000000000ull;
  //printf("Handle packet %s, %s\n", quad.to_string().c_str(), ps_type_str(ps_type).c_str());
  // Host portion vertical scans
  auto* h_ent = get_host_entry(quad.dst.address()); 
  h_ent->timeout = NOW+TIMEOUT;
  //increment or add scanned_from entry
  auto it = h_ent->scanned_from.find(quad.src.address());
  if(it != h_ent->scanned_from.end())
  {
    it->second.ctr++;
    it->second.timeout = NOW+PORTSHIT_TIMEOUT;
    it->second.type = ps_type;
  }
  else
    h_ent->scanned_from[quad.src.address()] = {1, NOW+SCANNED_TIMEOUT, ps_type};

  //increment or add ports_hit entry
  auto it2 = h_ent->ports_hit.find(quad.dst.port());
  if(it2 != h_ent->ports_hit.end())
  {
    it2->second.ctr++;
    it2->second.timeout = NOW+PORTSHIT_TIMEOUT;
    it2->second.type = ps_type;
  }
  else
    h_ent->ports_hit[quad.dst.port()] = {1, NOW+PORTSHIT_TIMEOUT, ps_type};

  //Port part horizontal scans
  auto* p_ent = get_port_entry(quad.dst.port()); 
  p_ent->timeout = NOW+TIMEOUT;

  auto it3 = p_ent->scanned_from.find(quad.src.address());
  if(it3 != p_ent->scanned_from.end())
  {
    it3->second.ctr++;
    it3->second.timeout = NOW+PORTSHIT_TIMEOUT;
    it3->second.type = ps_type;
  }
  else
    p_ent->scanned_from[quad.src.address()] = {1, NOW+SCANNED_TIMEOUT, ps_type};

  auto it4 = p_ent->hosts_hit.find(quad.dst.address());
  if(it4 != p_ent->hosts_hit.end())
  {
    it4->second.ctr++;
    it4->second.timeout = NOW+PORTSHIT_TIMEOUT;
    it4->second.type = ps_type;
  }
  else
    p_ent->hosts_hit[quad.dst.address()] = {1, NOW+HOSTSHIT_TIMEOUT, ps_type};

  return;
}

PortscanConntrack::Flood_entry* PortscanConntrack::get_flood_entry_syn(const Socket s) {
  auto it = synflood.find(s);
    if(it != synflood.end())
  return it->second.get();
  return add_flood_entry_syn(s);
}

PortscanConntrack::Flood_entry* PortscanConntrack::get_flood_entry_ack(const Socket s) {
  auto it = ackflood.find(s);
    if(it != ackflood.end())
  return it->second.get();
  return add_flood_entry_ack(s);
}

PortscanConntrack::Flood_entry* PortscanConntrack::get_flood_entry_udp(const Socket s) {
  auto it = udpflood.find(s);
    if(it != udpflood.end())
  return it->second.get();
  return add_flood_entry_udp(s);
}

PortscanConntrack::Flood_entry* PortscanConntrack::get_flood_entry_icmp(const net::Addr addr) {
  auto it = icmpflood.find(addr);
  if(it != icmpflood.end())
    return it->second.get();
  return add_flood_entry_icmp(addr);
}

PortscanConntrack::Flood_entry* PortscanConntrack::get_flood_entry(const Socket s, PS_type t)
{
  switch(t) {
    case PS_type::SYN_FLOOD:
      return get_flood_entry_syn(s);
    case PS_type::ACK_FLOOD:
      return get_flood_entry_ack(s);
    case PS_type::UDP_FLOOD:
      return get_flood_entry_udp(s);
    case PS_type::ICMP_FLOOD:
      return get_flood_entry_icmp(s.address());
    default:
      return nullptr;
  }
}

PortscanConntrack::Flood_entry* PortscanConntrack::add_flood_entry_ack(const Socket s)
{
  auto flood_entry = std::make_shared<Flood_entry>();
  ackflood.emplace(std::piecewise_construct,
    std::forward_as_tuple(s),
    std::forward_as_tuple(flood_entry));
  return flood_entry.get();
}

PortscanConntrack::Flood_entry* PortscanConntrack::add_flood_entry_syn(const Socket s)
{
  auto flood_entry = std::make_shared<Flood_entry>();
  synflood.emplace(std::piecewise_construct,
    std::forward_as_tuple(s),
    std::forward_as_tuple(flood_entry));
  return flood_entry.get();
}

PortscanConntrack::Flood_entry* PortscanConntrack::add_flood_entry_udp(const Socket s)
{
  auto flood_entry = std::make_shared<Flood_entry>();
  udpflood.emplace(std::piecewise_construct,
    std::forward_as_tuple(s),
    std::forward_as_tuple(flood_entry));
  return flood_entry.get();
}

PortscanConntrack::Flood_entry* PortscanConntrack::add_flood_entry_icmp(const net::Addr addr)
{
  auto flood_entry = std::make_shared<Flood_entry>();
  icmpflood.emplace(std::piecewise_construct,
    std::forward_as_tuple(addr),
    std::forward_as_tuple(flood_entry));
  return flood_entry.get();
}

PortscanConntrack::Port_entry* PortscanConntrack::get_port_entry(const port_t port)
{
  auto it = port_entries.find(port);

  if(it != port_entries.end())
    return it->second.get();
  return add_port_entry(port);
}

PortscanConntrack::Port_entry* PortscanConntrack::add_port_entry(const port_t port)
{
  // create the entry
  auto port_entry = std::make_shared<Port_entry>();

  //host_entries.emplace(addr, host_entry);
  port_entries.emplace(std::piecewise_construct,
    std::forward_as_tuple(port),
    std::forward_as_tuple(port_entry));

  return port_entry.get();
}

PortscanConntrack::Host_entry* PortscanConntrack::get_host_entry(const net::Addr addr)
{
  auto it = host_entries.find(addr);

  if(it != host_entries.end())
    return it->second.get();
  return add_host_entry(addr);
}

PortscanConntrack::Host_entry* PortscanConntrack::add_host_entry(const net::Addr addr)
{
  // Return nullptr if conntrack is full
  //if(UNLIKELY(maximum_entries != 0 and
  //  entries.size() + 2 > maximum_entries))
  //{
  //  CTDBG("<PortscanConntrack> Limit reached (limit=%lu sz=%lu)\n",
  //    maximum_entries, entries.size());
  //  return nullptr;
  //}

  //if(not flush_timer.is_running())
  //  flush_timer.start(flush_interval);

  // create the entry
  auto host_entry = std::make_shared<Host_entry>();

  //host_entries.emplace(addr, host_entry);
  host_entries.emplace(std::piecewise_construct,
    std::forward_as_tuple(addr),
    std::forward_as_tuple(host_entry));

  //update_timeout(*entry, timeout.unconfirmed);
  return host_entry.get();
}


Quadruple PortscanConntrack::get_quadruple(const PacketIP4& pkt)
{
  const auto* ports = reinterpret_cast<const uint16_t*>(pkt.ip_data().data());
  uint16_t src_port = ntohs(*ports);
  uint16_t dst_port = ntohs(*(ports + 1));

  return {{pkt.ip_src(), src_port}, {pkt.ip_dst(), dst_port}};
}

Quadruple PortscanConntrack::get_quadruple_icmp(const PacketIP4& pkt)
{
  Expects(pkt.ip_protocol() == Protocol::ICMPv4);

  struct partial_header {
    uint16_t  type_code;
    uint16_t  checksum;
    uint16_t  id;
  };

  // not sure if sufficent
  auto id = reinterpret_cast<const partial_header*>(pkt.ip_data().data())->id;

  return {{pkt.ip_src(), id}, {pkt.ip_dst(), id}};
}

PortscanConntrack::Entry* PortscanConntrack::in(const PacketIP4& pkt)
{
  const auto proto = pkt.ip_protocol();
  if(not flood_timer.is_running()){
    flood_timer.start(flood_interval);
  }
  switch(proto)
  {
    case Protocol::TCP:
      return tcp_in(*this, get_quadruple(pkt), pkt);

    case Protocol::UDP:
      return simple_track_in(get_quadruple(pkt), proto);

    case Protocol::ICMPv4:
      return simple_track_in(get_quadruple_icmp(pkt), proto);

    default:
      return nullptr;
  }
}

PortscanConntrack::Entry* PortscanConntrack::confirm(const PacketIP4& pkt)
{
  const auto proto = pkt.ip_protocol();

  auto quad = [&]()->Quadruple {
    switch(proto)
    {
      case Protocol::TCP:
      case Protocol::UDP:
        return get_quadruple(pkt);

      case Protocol::ICMPv4:
        return get_quadruple_icmp(pkt);

      default:
        return Quadruple();
    }
  }();

  return confirm(quad, proto);
}

PortscanConntrack::Entry* PortscanConntrack::confirm(Quadruple quad, const Protocol proto)
{
  auto* entry = get(quad, proto);

  if(UNLIKELY(entry == nullptr)) {
    CTDBG("<PortscanConntrack> Entry not found on confirm, checking swapped: %s\n",
      quad.to_string().c_str());
    // the packet my be NATed. note: not sure if this is good
    if(UNLIKELY((entry = get(quad.swap(), proto)) == nullptr)) {
      return nullptr;
    }
  }

  if(entry->state == State::UNCONFIRMED)
  {
    CTDBG("<PortscanConntrack> Confirming %s\n", entry->to_string().c_str());
    entry->state = State::NEW;
    update_timeout(*entry, timeout.confirmed);
  }

  return entry;
}

PortscanConntrack::Entry* PortscanConntrack::add_entry(
  const Quadruple& quad, const Protocol proto)
{
  // Return nullptr if conntrack is full
  if(UNLIKELY(maximum_entries != 0 and
    entries.size() + 2 > maximum_entries))
  {
    CTDBG("<PortscanConntrack> Limit reached (limit=%lu sz=%lu)\n",
      maximum_entries, entries.size());
    return nullptr;
  }

  if(not flush_timer.is_running())
    flush_timer.start(flush_interval);

  // we dont check if it's already exists
  // because it should be called from in()

  // create the entry
  auto entry = std::make_shared<Entry>(quad, proto);

  entries.emplace(std::piecewise_construct,
    std::forward_as_tuple(entry->first, proto),
    std::forward_as_tuple(entry));

  entries.emplace(std::piecewise_construct,
    std::forward_as_tuple(entry->second, proto),
    std::forward_as_tuple(entry));

  CTDBG("<PortscanConntrack> Entry added: %s\n", entry->to_string().c_str());

  update_timeout(*entry, timeout.unconfirmed);

  return entry.get();
}

PortscanConntrack::Entry* PortscanConntrack::update_entry(
  const Protocol proto, const Quadruple& oldq, const Quadruple& newq)
{
  // find the entry that has quintuple containing the old quant
  const auto quint = Quintuple{oldq, proto};
  auto it = entries.find(quint);

  if(UNLIKELY(it == entries.end())) {
    CTDBG("<PortscanConntrack> Cannot find entry when updating: %s\n",
      oldq.to_string().c_str());
    return nullptr;
  }

  auto entry = it->second;

  // determine if the old quant hits the first or second quantuple
  auto& quad = (entry->first == oldq)
    ? entry->first : entry->second;

  // give it a new value
  quad = newq;

  // TODO: this could probably be optimized with C++17 map::extract
  // erase the old entry
  entries.erase(quint);
  // insert the entry with updated quintuple
  entries.emplace(std::piecewise_construct,
    std::forward_as_tuple(newq, proto),
    std::forward_as_tuple(entry));

  CTDBG("<PortscanConntrack> Entry updated: %s\n", entry->to_string().c_str());

  return entry.get();
}

void PortscanConntrack::alert_flood(const Socket s, const std::shared_ptr<Flood_entry> f_ent, const char* str, const net::Addr min, const net::Addr max) const {
  printf("%s in progess, %s, sources: %lu, %s:%s\n", str, s.to_string().c_str(), f_ent->source.size(), min.to_string().c_str(), max.to_string().c_str());
  return;
}

void PortscanConntrack::alert_flood_icmp(const net::Addr a, const std::shared_ptr<Flood_entry> f_ent, const char* str, const net::Addr min, const net::Addr max) const {
  printf("%s in progess, %s, sources: %lu, %s:%s\n", str, a.to_string().c_str(), f_ent->source.size(), min.to_string().c_str(), max.to_string().c_str());
  return;
}
void PortscanConntrack::alert_vertical_portscan(const net::Addr& host, Host_entry& h_ent) {
  uint16_t ctr[(uint8_t)PS_type::MAX_ELEMENTS] = {0};
  std::ostringstream stringStream;
  stringStream << "{\"host\": \"" << host.to_string() << "\",\"alerted\": ";
  stringStream << (h_ent.alerted ? "true," : "false,");
  stringStream << "\"time\": " << uint64_t(RTC::boot_timestamp() + RTC::nanos_now()/1000000000ul) << ",\n";
  stringStream << "\"scanned_from\": [\n";
  auto first = true;
  for(auto it = h_ent.scanned_from.begin(); it != h_ent.scanned_from.end();it++) {
    if(!first) stringStream << ",\n";
    else first=false;
    stringStream << "{\"ip\": \"" << it->first.to_string() << "\", \"ctr\": " << it->second.ctr;
    stringStream  << ", \"type\": \"" << ps_type_str(it->second.type) << "\"}";
  }
  stringStream << "],\n\"ports_scanned\": { \"amount\":" << h_ent.ports_hit.size() << ",";
  //stringStream << "]\n\"ports_scanned\": [\n";
  port_t min = 0xffff; port_t max = 0;
  for(auto it2 = h_ent.ports_hit.begin(); it2 != h_ent.ports_hit.end();it2++) {
    if(it2->first < min) min = it2->first;
    if(it2->first > max) max = it2->first;
    //stringStream << "{\"port\": " << it2->first << ", \"ctr\": " << it2->second.ctr << "},\n";
    ctr[(uint8_t)it2->second.type]++;
  }
  stringStream << "\"min\": " << min << ", \"max\": " << max << ",";
  //stringStream << "],\n";
  stringStream << "\"scan_type\": [\n";
  first = true;
  for(size_t i = 0; i<(uint8_t)PS_type::MAX_ELEMENTS; i++) {
    if(ctr[i] > 0) {
      if(!first) stringStream << ",\n";
      else first=false;
      stringStream << "{\"type\": \"" << ps_type_str((PS_type)i) << "\", \"ctr\": " << ctr[i] << "}";
    }
  }
  stringStream << "]}}\n";
  //if(!h_ent.alerted) {
  printf("%s", stringStream.str().c_str());
  //}
  if(!h_ent.alerted) h_ent.alerted = true;
}

void PortscanConntrack::alert_horizontal_portscan(const port_t& port, Port_entry& p_ent) const {
  uint16_t ctr[(uint8_t)PS_type::MAX_ELEMENTS] = {0};
  std::ostringstream stringStream;
  stringStream << "{\"port\": \"" << port << "\",\"alerted\": ";
  stringStream << (p_ent.alerted ? "true," : "false,");
  stringStream << "\"time\": " << uint64_t(RTC::boot_timestamp() + RTC::nanos_now()/1000000000ul) << ",\n";
  stringStream << "\"scanned_from\": [\n";
  auto first = true;
  for(auto it = p_ent.scanned_from.begin(); it != p_ent.scanned_from.end();it++) {
    if(!first) stringStream << ",\n";
    else first=false;
    stringStream << "{\"ip\": \"" << it->first.to_string() << "\", \"ctr\": " << it->second.ctr << "}";
  }
  stringStream << "],\n\"hosts_scanned\": { \"amount\":" << p_ent.hosts_hit.size() << ",[";
  for(auto it2 = p_ent.hosts_hit.begin(); it2 != p_ent.hosts_hit.end();it2++) {
    if(!first) stringStream << ",\n";
    else first=false;
    stringStream << "{\"host\": " << it2->first.to_string() << ", \"ctr\": " << it2->second.ctr << "}";
    ctr[(uint8_t)it2->second.type]++;
  }
  stringStream << "],\n";
  stringStream << "\"scan_type\": [\n";
  first = true;
  for(size_t i = 0; i<(uint8_t)PS_type::MAX_ELEMENTS; i++) {
    if(ctr[i] > 0) {
      if(!first) stringStream << ",\n";
      else first=false;
      stringStream << "{\"type\": \"" << ps_type_str((PS_type)i) << "\", \"ctr\": " << ctr[i] << "}";
    }
  }
  stringStream << "]}}\n";
  //if(!p_ent.alerted) {
  printf("%s", stringStream.str().c_str());
  //}
  if(!p_ent.alerted) p_ent.alerted = true;
}

void PortscanConntrack::open_port_remove_expired()
{
  CTDBG("<PortscanConntrack> open port entries size: %u\n", open_ports.size());
  const auto NOW = RTC::nanos_now()/1000000000ull;
  for(auto it = open_ports.begin(); it != open_ports.end();)
  {
    if(it->second > NOW) {
      ++it;
    }
    else {
      CTDBG("<PortscanConntrack> Erasing open port %s\n", it->first.to_string().c_str());
      it = open_ports.erase(it);
    }
  }
}

void PortscanConntrack::port_remove_expired()
{
  CTDBG("<PortscanConntrack> port entries size: %u\n", port_entries.size());
  const auto NOW = RTC::nanos_now()/1000000000ull;
  for(auto it = port_entries.begin(); it != port_entries.end();)
  {
    for(auto it2 = it->second->scanned_from.begin(); it2 != it->second->scanned_from.end();)
    {
      if(it2->second.timeout > NOW) {
        ++it2;
      }
      else {
        CTDBG("<PortscanConntrack> Erasing port_entry %u ->scanned_from  %s\n", it->first, it2->first.to_string().c_str());
        it2 = it->second->scanned_from.erase(it2);
      }
    }
    for(auto it3 = it->second->hosts_hit.begin(); it3 != it->second->hosts_hit.end();)
    {
      if(it3->second.timeout > NOW) {
        ++it3;
      }
      else {
        CTDBG("<PortscanConntrack> Erasing port_entry %u ->hosts_hit %s\n", it->first, it3->first.to_string().c_str());
        it3 = it->second->hosts_hit.erase(it3);
      }
    }
    if(it->second->timeout > NOW) {
      if(it->second->hosts_hit.size() >= THRESHOLD_HOSTSHIT) {
        alert_horizontal_portscan(it->first, *(it->second));
        //it->second->alerted = true;
      }
      ++it;
    }
    else {
      CTDBG("<PortscanConntrack> Erasing port_entry %u\n", it->first);
      it = port_entries.erase(it);
    }
  }
}

void PortscanConntrack::host_remove_expired()
{
  CTDBG("<PortscanConntrack> host entries size: %u\n", host_entries.size());
  const auto NOW = RTC::nanos_now()/1000000000ull;
  for(auto it = host_entries.begin(); it != host_entries.end();)
  {
    for(auto it2 = it->second->scanned_from.begin(); it2 != it->second->scanned_from.end();)
    {
      if(it2->second.timeout > NOW) {
        ++it2;
      }
      else {
        CTDBG("<PortscanConntrack> Erasing host_entry %s ->scanned_from  %s\n", it->first.to_string().c_str(), it2->first.to_string().c_str());
        it2 = it->second->scanned_from.erase(it2);
      }
    }
    for(auto it3 = it->second->ports_hit.begin(); it3 != it->second->ports_hit.end();)
    {
      if(it3->second.timeout > NOW) {
        ++it3;
      }
      else {
        CTDBG("<PortscanConntrack> Erasing host_entry %s ->ports_hit %u\n", it->first.to_string().c_str(), it3->first);
        it3 = it->second->ports_hit.erase(it3);
      }
    }
    if(it->second->timeout > NOW) {
      if(it->second->ports_hit.size() >= THRESHOLD_PORTSHIT) {
        alert_vertical_portscan(it->first, *(it->second));
        //it->second->alerted = true;
      }
      ++it;
    }
    else {
      CTDBG("<PortscanConntrack> Erasing host_entry %s\n", it->first.to_string().c_str());
      it = host_entries.erase(it);
    }
  }
}

void PortscanConntrack::remove_expired()
{
  CTDBG("<PortscanConntrack> Removing expired entries\n");
  CTDBG("<PortscanConntrack> entries size: %u\n", entries.size());
  const auto NOW = RTC::nanos_now()/1000000000ull;
  // entries data structure
  for(auto it = entries.begin(); it != entries.end();)
  {
    if(it->second->timeout > NOW) {
      ++it;
    }
    else {
      CTDBG("<PortscanConntrack> Erasing %s\n", it->second->to_string().c_str());
      if(static_cast<net::tcp::Ct_state>(it->second->other) == net::tcp::Ct_state::SYN_RECV and it->second->first == it->first.quad)
      {
        handle_scan_packet(it->second->first, PortscanConntrack::PS_type::SYN_OPEN);
      }
      if(static_cast<net::tcp::Ct_state>(it->second->other) == net::tcp::Ct_state::SYN_SENT and it->second->first == it->first.quad)
      {
        handle_scan_packet(it->second->first, PortscanConntrack::PS_type::SYN_NOREPLY);
      }
      it = entries.erase(it);
    }
  }
}

PortscanConntrack::flood_helper_return PortscanConntrack::flood_helper(std::shared_ptr<Flood_entry> f_ent)
{
  uint32_t ctr = 0;
  net::Addr min, max;
  bool first  = true;
  for(auto it = f_ent->source.begin(); it != f_ent->source.end();)
  {
    if(first){ min=it->first; max=it->first; first=false;}
    else {
      if(it->first<min) min=it->first;
      if(it->first>max) max=it->first;
    }
    if(it->second.ctr == 0)
      it = f_ent->source.erase(it);
    else {
      ctr += it->second.ctr;
      it->second.ctr = 0;
      ++it;
    }
  }
  return {ctr, min, max};
}

void PortscanConntrack::on_flood_timeout()
{
  for(auto it = synflood.begin(); it != synflood.end();){
    auto tmp = flood_helper(it->second);
    if(tmp.ctr > syn_flood_threshold)
      alert_flood(it->first, it->second, "SYN Flood", tmp.min, tmp.max);
    ++it;
  }
  for(auto it2= ackflood.begin(); it2 != ackflood.end();){
    auto tmp = flood_helper(it2->second);
    if(tmp.ctr > ack_flood_threshold)
      alert_flood(it2->first, it2->second, "ACK Flood", tmp.min, tmp.max);
    ++it2;
  }
  for(auto it3 = udpflood.begin(); it3 != udpflood.end();){
    auto tmp = flood_helper(it3->second);
    if(tmp.ctr > udp_flood_threshold)
      alert_flood(it3->first, it3->second, "UDP Flood", tmp.min, tmp.max);
    ++it3;
  }
  for(auto it4 = icmpflood.begin(); it4 != icmpflood.end();){
    auto tmp = flood_helper(it4->second);
    if(tmp.ctr > syn_flood_threshold)
      alert_flood_icmp(it4->first, it4->second, "ICMP Flood", tmp.min, tmp.max);
    ++it4;
  }
  flood_timer.restart(flood_interval);
}

void PortscanConntrack::on_timeout()
{
  remove_expired();
  open_port_remove_expired();
  port_remove_expired();
  host_remove_expired();
  auto rx_dropped_packets = Statman::get().get_by_name("eth0.rx_refill_dropped").get_uint64();
  auto rx_total_packets = Statman::get().get_by_name("eth0.stat_rx_total_packets").get_uint64();
  auto rx_total_bytes = Statman::get().get_by_name("eth0.stat_rx_total_bytes").get_uint64();
  auto rx_ethernet_packets = Statman::get().get_by_name("eth0.ethernet.packets_rx").get_uint64();
  //printf("Packets received ethernet: %lu, Packets received: %lu, Bytes received: %lu, Packets dropped: %lu\n", rx_ethernet_packets, rx_total_packets, rx_total_bytes, rx_dropped_packets);
  printf("Packets received: %lu, Packets dropped: %lu, Time: %lu\n", rx_total_packets, rx_dropped_packets, uint64_t(RTC::boot_timestamp() + RTC::nanos_now()/1000000000ul));

  if(not entries.empty() or not host_entries.empty() or not port_entries.empty())
    flush_timer.restart(flush_interval);
}

int PortscanConntrack::Entry::deserialize_from(void* addr)
{
  auto& entry = *reinterpret_cast<Entry*>(addr);
  this->first   = entry.first;
  this->second  = entry.second;
  this->timeout = entry.timeout;
  this->proto   = entry.proto;
  this->state   = entry.state;
  this->flags   = entry.flags;
  this->other   = entry.other;
  return sizeof(Entry) - sizeof(on_close);
}

void PortscanConntrack::Entry::serialize_to(std::vector<char>& buf) const
{
  const size_t size = sizeof(Entry) - sizeof(on_close);
  const auto* ptr = reinterpret_cast<const char*>(this);
  buf.insert(buf.end(), ptr, ptr + size);
}

int PortscanConntrack::deserialize_from(void* addr)
{
  const auto prev_size = entries.size();
  auto* buffer = reinterpret_cast<uint8_t*>(addr);

  const auto size = *reinterpret_cast<size_t*>(buffer);
  buffer += sizeof(size_t);
  size_t dupes = 0;
  for(auto i = size; i > 0; i--)
  {
    // create the entry
    auto entry = std::make_shared<Entry>();
    buffer += entry->deserialize_from(buffer);

    bool insert = false;
    insert = entries.insert_or_assign({entry->first, entry->proto}, entry).second;
    if(not insert)
      dupes++;
    insert = entries.insert_or_assign({entry->second, entry->proto}, entry).second;
    if(not insert)
      dupes++;
  }
  Ensures(entries.size() - (prev_size-dupes) == size * 2);

  return buffer - reinterpret_cast<uint8_t*>(addr);
}

void PortscanConntrack::serialize_to(std::vector<char>& buf) const
{
  int unserialized = 0;

  // Since each entry is stored twice in the map,
  // we iterate and put it in a set if not already there
  std::set<Entry*> to_serialize;
  for(auto& i : entries)
  {
    auto* ent = i.second.get();

    // We cannot restore delegates, so just ignore
    // the ones with close handler set
    if(ent->on_close != nullptr) {
      unserialized++;
      continue;
    }
    // If not in set, add
    if(to_serialize.find(ent) == to_serialize.end())
      to_serialize.emplace(ent);
  }

  // Serialize number of entries
  size_t size = to_serialize.size();
  const auto* size_ptr = reinterpret_cast<const char*>(&size);

  const auto expected_buf_size = sizeof(size) + (size * (sizeof(Entry) - sizeof(Entry_handler)));
  buf.reserve(expected_buf_size);

  buf.insert(buf.end(), size_ptr, size_ptr + sizeof(size));
  // Serialize each entry
  for(auto& ent : to_serialize)
    ent->serialize_to(buf);

  if(unserialized > 0)
    INFO("PortscanConntrack", "%i entries not serialized\n", unserialized);
}


}
