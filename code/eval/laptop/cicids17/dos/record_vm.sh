#!/bin/bash    
psrecord $1 --interval 0.5 --log includeos.txt --include-children &
psrecord $1 --interval 5 --log includeos5.txt --include-children &
psrecord $2 --interval 0.5 --log snort.txt --include-children &
psrecord $2 --interval 5 --log snort5.txt --include-children &
