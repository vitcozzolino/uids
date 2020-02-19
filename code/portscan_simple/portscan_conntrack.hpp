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

#pragma once
#ifndef PORTSCAN_CONNTRACK_HPP
#define PORTSCAN_CONNTRACK_HPP

#include <net/socket.hpp>
#include <net/ip4/packet_ip4.hpp>
#include <vector>
#include <unordered_map>
#include <rtc>
#include <chrono>
#include <util/timer.hpp>

namespace net {

class PortscanConntrack {
public:
  struct Entry;
  using Entry_ptr = const Entry*;
  /**
   * Custom handler for tracking packets in a certain way
   */
  using Packet_tracker = delegate<Entry*(PortscanConntrack&, Quadruple, const PacketIP4&)>;

  using Entry_handler = delegate<void(Entry*)>;

  /**
   * @brief      Key for lookup tables
   */
  struct Quintuple {
    Quadruple quad;
    Protocol  proto;

    Quintuple(Quadruple q, const Protocol p)
      : quad(std::move(q)), proto(p)
    {}

    bool operator==(const Quintuple& other) const noexcept
    { return proto == other.proto and quad == other.quad; }

    bool operator<(const Quintuple& other) const noexcept {
      return proto < other.proto
        or (proto == other.proto and quad < other.quad);
    }
  };

  /**
   * @brief      Hasher for Quintuple
   */
  struct Quintuple_hasher
  {
    std::size_t operator()(const Quintuple& key) const noexcept
    {
      const auto h1 = std::hash<Quadruple>{}(key.quad);
      const auto h2 = std::hash<uint8_t>{}(static_cast<uint8_t>(key.proto));
      return h1 ^ h2;
    }
  };

  /**
   * @brief     Hasher for net::Addr
   */
  struct Addr_hasher 
  {
    std::size_t operator()(const net::Addr& addr) const noexcept
    {
      return addr.v6().i64[0] ^ addr.v6().i64[1];
    }
  };

  /**
   * @brief      The type of suspected portscan attempt
   */
  enum class PS_type : uint8_t {
    SYN_NOREPLY = 0, //inactive/filtered host
    SYN_CLOSED = 1,   //active host but closed port
    SYN_OPEN = 2,     //active host open port
    XMAS_SCAN = 3,
    FIN_SCAN = 4,
    NULL_SCAN = 5,
    UDP_SCAN = 6,
    SYN_FLOOD = 7,
    ACK_FLOOD = 8,
    UDP_FLOOD = 9,
    ICMP_FLOOD = 10,
    MAX_ELEMENTS = 11, // always last!
  };

  /*
   * @brief      To string function for enum PS_type
   */
  std::string ps_type_str(const PortscanConntrack::PS_type ps_type) const;

  /**
   * @brief      The state of the connection.
   */
  enum class State : uint8_t {
    NEW,
    ESTABLISHED,
    RELATED,
    UNCONFIRMED // not sure about this one
  };

  enum class Flag : uint8_t {
    UNREPLIED   = 1 << 0,
    ASSURED     = 1 << 1
  };

  /**
   * @brief      A entry in the connection tracker (a Connection)
   */
  struct Entry {
    Quadruple         first;
    Quadruple         second;
    RTC::timestamp_t  timeout;
    Protocol          proto;
    State             state;
    uint8_t           flags{0x0};
    uint8_t           other{0x0}; // whoever can make whatever here
    Entry_handler     on_close;

    Entry(Quadruple quad, Protocol p)
      : first{std::move(quad)}, second{first.dst, first.src},
        proto(p), state(State::UNCONFIRMED), on_close(nullptr)
    {}

    Entry() = default;

    bool is_mirrored() const noexcept
    { return first.src == second.dst and first.dst == second.src; }

    std::string to_string() const;

    ~Entry();

    int deserialize_from(void*);
    void serialize_to(std::vector<char>&) const;

    void set_flag(const Flag f)
    { flags |= static_cast<uint8_t>(f); }

    void unset_flag(const Flag f)
    { flags &= ~static_cast<uint8_t>(f); }

    bool isset(const Flag f) const noexcept
    { return flags & static_cast<uint8_t>(f); }

  };

  using port_t = uint16_t;

  struct ctr_time {
    uint16_t ctr;
    RTC::timestamp_t timeout;
    PS_type type;
  };

  struct ctr_type {
    uint32_t ctr;
    PS_type type;
  };
  
  struct flood_helper_return {
    uint32_t ctr;
    net::Addr min;
    net::Addr max;
  };

  using Scanned_from = std::unordered_map<net::Addr, ctr_time, Addr_hasher>;
  using Ports_hit = std::unordered_map<port_t, ctr_time>; // probably uint8_t would be enough here
  using Hosts_hit = std::unordered_map<net::Addr, ctr_time, Addr_hasher>;

  struct Host_entry {
    Scanned_from scanned_from;
    Ports_hit ports_hit;
    RTC::timestamp_t timeout;
    bool alerted = false;
  };

  struct Port_entry {
    Scanned_from scanned_from;
    Hosts_hit hosts_hit;
    RTC::timestamp_t timeout;
    bool alerted = false;
  };

  struct Flood_entry {
    std::unordered_map<net::Addr, ctr_type, Addr_hasher> source;
  };


  using Timeout_duration = std::chrono::seconds;
  struct Timeout_settings {
    Timeout_duration tcp;
    Timeout_duration udp;
    Timeout_duration icmp;

    Timeout_duration get(const Protocol proto) const noexcept
    {
      switch(proto) {
        case Protocol::TCP: return tcp;
        case Protocol::UDP: return udp;
        case Protocol::ICMPv4: return icmp;
        default: return Timeout_duration{0};
      }
    }
  };

public:
  /** Maximum number of conntrack entries. */
  // 0 means unlimited. Every new connection result in 2 entries.
  size_t maximum_entries;
  size_t syn_flood_threshold;
  size_t ack_flood_threshold;
  size_t udp_flood_threshold;
  size_t icmp_flood_threshold;

  struct {
    Timeout_settings unconfirmed{ .tcp  = Timeout_duration{10},
                                  .udp  = Timeout_duration{10},
                                  .icmp = Timeout_duration{10}};

    Timeout_settings confirmed  { .tcp  = Timeout_duration{30},
                                  .udp  = Timeout_duration{10},
                                  .icmp = Timeout_duration{10}};

    Timeout_settings established{ .tcp  = Timeout_duration{300},
                                  .udp  = Timeout_duration{10},
                                  .icmp = Timeout_duration{10}};
  } timeout;
  /**
   * @brief      Find the entry for the given packet
   *
   * @param[in]  pkt   The packet
   *
   * @return     A matching conntrack entry (nullptr if not found)
   */
  Entry* get(const PacketIP4& pkt) const;

  /**
   * @brief      Find the entry where the quadruple
   *             with the given protocol matches.
   *
   * @param[in]  quad   The quad
   * @param[in]  proto  The prototype
   *
   * @return     A matching conntrack entry (nullptr if not found)
   */
  Entry* get(const Quadruple& quad, const Protocol proto) const;

  bool isopen(const Socket) const;
  bool add_open_port(const Socket s);

  /**
   * @brief      Handle the packet of a suspected scan
   *
   * @param[in]  quad   The quad with src/dst matching the SYN packet
   *
   */
  void handle_scan_packet(const Quadruple& quad, const PS_type ps_type);
  void handle_flood_packet(const Quadruple& quad, const PS_type ps_type);
  flood_helper_return flood_helper(std::shared_ptr<Flood_entry> f_ent);
  Port_entry* get_port_entry(const port_t port);
  Port_entry* add_port_entry(const port_t port);
  Host_entry* get_host_entry(const net::Addr addr);
  Host_entry* add_host_entry(const net::Addr addr);
  Flood_entry* get_flood_entry(const Socket s, const PS_type t);
  Flood_entry* get_flood_entry_syn(const Socket s);
  Flood_entry* get_flood_entry_ack(const Socket s);
  Flood_entry* get_flood_entry_udp(const Socket s);
  Flood_entry* get_flood_entry_icmp(const net::Addr addr);
  Flood_entry* add_flood_entry_syn(const Socket s);
  Flood_entry* add_flood_entry_ack(const Socket s);
  Flood_entry* add_flood_entry_udp(const Socket s);
  Flood_entry* add_flood_entry_icmp(const net::Addr addr);

  void alert_flood(const Socket s, const std::shared_ptr<Flood_entry> f_ent, const char* str, const net::Addr min, const net::Addr max) const;
  void alert_flood_icmp(const net::Addr a, const std::shared_ptr<Flood_entry> f_ent, const char* str, const net::Addr min, const net::Addr max) const;
  void alert_vertical_portscan(const net::Addr& host, Host_entry& h_ent);
  void alert_horizontal_portscan(const port_t& port, Port_entry& p_ent) const;
  void open_port_remove_expired();
  void port_remove_expired();
  void host_remove_expired();

  /**
   * @brief      Track a packet, updating the state of the entry.
   *
   * @param[in]  pkt   The packet
   *
   * @return     The conntrack entry related to this packet.
   */
  Entry* in(const PacketIP4& pkt);

  /**
   * @brief      Confirms a connection, moving the entry to confirmed.
   *
   * @param[in]  pkt   The packet
   *
   * @return     The confirmed entry, if any
   */
  Entry* confirm(const PacketIP4& pkt);

  /**
   * @brief      Confirms a connection, moving the entry to confirmed
   *             and indexing it both ways.
   *
   * @param[in]  quad   The quad
   * @param[in]  proto  The prototype
   *
   * @return     The confirmed entry, if any
   */
  Entry* confirm(Quadruple quad, const Protocol proto);

  /**
   * @brief      Adds an entry as unconfirmed, mirroring the quadruple.
   *
   * @param[in]  quad   The quadruple
   * @param[in]  proto  The prototype
   * @param[in]  dir    The direction the packet is going
   *
   * @return     The created entry
   */
  Entry* add_entry(const Quadruple& quad, const Protocol proto);

  /**
   * @brief      Update one quadruple of a old entry (proto + oldq)
   *             to a new Quadruple. This changes the entry and updates the key.
   *
   * @param[in]  proto  The protocol
   * @param[in]  oldq   The old (current) quadruple
   * @param[in]  newq   The new quadruple
   */
  Entry* update_entry(const Protocol proto, const Quadruple& oldq, const Quadruple& newq);

  /**
   * @brief      Remove all expired entries, both confirmed and unconfirmed.
   */
  void remove_expired();

  /**
   * @brief      Number of entries currently tracked.
   *
   * @return     Number of entries.
   */
  size_t number_of_entries() const noexcept
  { return entries.size(); }

  /**
   * @brief      Call reserve on the underlying unordered_map
   *
   * @param[in]  count  The count
   */
  void reserve(size_t count)
  { entries.reserve(count); }

  /**
   * @brief      A very simple and unreliable way for tracking quintuples.
   *
   * @param[in]  quad   The quad
   * @param[in]  proto  The prototype
   *
   * @return     The conntrack entry related to quintuple.
   */
  Entry* simple_track_in(Quadruple quad, const Protocol proto);

  /**
   * @brief      Gets the quadruple from a IP4 packet.
   *             Assumes the packet has protocol specific payload.
   *
   * @param[in]  pkt   The packet
   *
   * @return     The quadruple.
   */
  static Quadruple get_quadruple(const PacketIP4& pkt);

  /**
   * @brief      Gets the quadruple from a IP4 packet carrying
   *             ICMP payload
   *
   * @param[in]  pkt   The packet
   *
   * @return     The quadruple for ICMP.
   */
  static Quadruple get_quadruple_icmp(const PacketIP4& pkt);

  /**
   * @brief      Construct a PortscanConntrack with unlimited maximum entries.
   */
  PortscanConntrack();

  /**
   * @brief      Construct a PortscanConntrack with a given limit of entries.
   *
   * @param[in]  max_entries  The maximum number of entries
   */
  PortscanConntrack(size_t max_entries);

  /** How often the flush timer should fire */
  std::chrono::seconds flush_interval {10};

  /** How often the syn_flood timer should fire */
  std::chrono::seconds flood_interval {1};

  /** Custom TCP handler can (and should) be added here */
  Packet_tracker tcp_in;

  int deserialize_from(void*);
  void serialize_to(std::vector<char>&) const;

private:
  using Entry_table = std::unordered_map<Quintuple, std::shared_ptr<Entry>, Quintuple_hasher>;
  Entry_table entries;
  using Hosts_scanned = std::unordered_map<net::Addr, std::shared_ptr<Host_entry>, Addr_hasher>;
  Hosts_scanned host_entries;
  using Ports_scanned = std::unordered_map<port_t, std::shared_ptr<Port_entry>>;
  Ports_scanned port_entries;
  using Dosmap = std::unordered_map<Socket, std::shared_ptr<Flood_entry>>;
  Dosmap synflood;
  Dosmap ackflood;
  Dosmap udpflood;
  std::unordered_map<net::Addr, std::shared_ptr<Flood_entry>, Addr_hasher> icmpflood;
  //used to track open ports (TCP Syn can be ignored under high load)
  using Open_ports = std::unordered_map<Socket, RTC::timestamp_t>;
  Open_ports open_ports;
  Timer       flush_timer;
  Timer       flood_timer;

  inline void update_timeout(Entry& ent, const Timeout_settings& timeouts);

  void on_timeout();
  void on_flood_timeout();

};

inline void PortscanConntrack::update_timeout(Entry& ent, const Timeout_settings& timeouts)
{
  ent.timeout = RTC::nanos_now()/1000000000ull + timeouts.get(ent.proto).count();
}

}

#endif
