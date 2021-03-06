# Abstract

The advent of the Internet of Things promises to interconnect all type of devices, including the most common
electrical appliances such as ovens and light bulbs. One of the greatest risks of the uncontrolled proliferation of resource constrained devices are the security and privacy implications.

Most manufacturers’ top priority is getting their product into the market quickly, rather than taking the necessary steps
to build security from the start, due to high competitiveness of the field. Moreover, standard security tools are tailored to server-class machines and not directly applicable in the IoT domain.

To address these problems, we propose a lightweight, signature-based intrusion detection system for IoT to be able to run on resource-constrained devices. Our prototype is based on the IncludeOS unikernel, ensuring low resource utilization, high modularity, and a minimalist code surface. In particular, we evaluate the performance of our solution on x86 and ARM devices and compare it against Snort, a widely known network intrusion detection system. The experimental results show that our prototype effectively detects all attack patterns while using up to 2-3x less CPU and 8x less RAM than our baseline.

# UIDS

This repo contains the code for UIDS, our unikernel-based IDS. The paper discussing UIDS was accepted at DISS 2020 and the pre-print version can be found [here](http://homepage.tudelft.nl/8e79t/files/pre-print-diss2020.pdf).


# Installing and Running
Install IncludeOS as shown at https://www.includeos.org/  
Build portscan\_simple similar to their hello\_world example  
Boot the portdetect image with `boot portdetect --create-bridge`  

To get traffic to the virtual machine use the newly created network bridge bridge43.  
It can be helpful to remove IP addresses from this bridge or set up a new network namespace to make sure no packets are sent up the network stack of the bridge interface.  

Disable caching of MAC addresses on the bridge with `brctl setageing bridge43 0` if you have issues with some frames not being routed to the tap interface of the virtual machine.
