#!/bin/bash
sed $1 -e "s/^ \+//g" | sed -e "s/ \+/,/g" > ${1%.txt}.csv
sed -i "1cElapsed time,CPU,RAM,VIRTUAL_RAM" ${1%.txt}.csv
