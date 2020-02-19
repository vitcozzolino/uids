# Notes

# IncludeOS packet path

Driver virto (virtionet.hpp) 
  -> net::Link\_layer<net::Ethernet>  (link\_layer.hpp)
    -> net::Ethernet::receive() (ethernet.cpp)
      -> dispatched to upstream delegates ip4\_upstream, ip6\_upstream, arp\_upstream, vlan\_upstream

VirtioNet::msix\_recv\_handler()
net::Link\_layer::receive() // hook into here for full ethernet packet (possibly change Protocol Type)
net::Ethernet::receive()


# Device registration for a virtual NIC without using NaCl
  using NaCl: use file e.g. iface.nacl with 
          Iface eth0 {
            index: 0
          }

  TODO figure out how this code is translated by the NaCl parser

# Traffic passthrough from host to guest(includeos service)

NIC PCI passthrough, solve:
  - IncludeOS instance needs drivers for physical NIC
  - Find qemu parameters used by 'boot' utility

Network bridge:
  IncludeOS creates and uses a bridge called bridge43 with TAP networking (layer2)
  Simply add ethernet interface of host to the bridge, should give packets to the guest.
  TODO test if this works
  brctl addif <iface\_name>

# TODO research/background
  # IDS (network) [exclude HIDS]
    notification
    detection
    existing approaches (minimal like click os, broad ones like snort etc.)
    attacks? 
    design patterns?
    
  # Unikernels
    IncludeOS, MirageOS, etc.

  # Motivation? Iot? Cloud? 
  
  # Latex template
  
  # use NaCl to configure IDS ruleset?

# TODO code
  notification system
    -> IncludeOS allows logging to UDP (usecase?)
  Full Ethernet packet capture (probably need to expand IncludeOS, implement Capture Protocol type [in addition to existing Ethernet]?)
  Maybe write files into host os filesystem? Probably better to use second network card (might be possible to run bare metal on arm in the future)
  
  Compartmentualize:
    Sniffer
    Preprocessors (skip for now)
    Detection (limited scope [portscan/ddos])
    Alert (use second network interface (udp/tcp) or shared disk space on host)


# TODO Evaluation
  research methods used to evaluate includeos (2 masterthesis so far)
  ARM support to run IDS image on RasberryPi in development by IncludeOS team (work started Jan 2019)
  etc.

# TODO Portscan
Fragmented IP packets detect ports
includeos connections are saved in std::unordered_map<tcp::Connection::Tuple, tcp::Connection_ptr>; 


# Stream handling in Snort
spp_stream4.c

# Papers
High performance Multi-rule inspection engine - aho-corasick, wu-manber, boyer-moore

# Testing
sudo ip r add local 1.0.0.0/8 dev eth0
sudo ip a add 10.0.0.1/24 dev eth0
sudo ip r add default via 10.0.0.2
sudo arp -s 10.0.02 xx:yy:xx:yy:xx;yy
