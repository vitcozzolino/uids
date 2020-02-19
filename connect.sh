#!/bin/bash
for port in `seq 50000 52000`;
do nc 10.200.200.44 $port < /dev/urandom &
done;
