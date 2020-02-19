#!/bin/bash
for port in `seq 50000 52000`;
do nc -l $port > /dev/null &
done;
