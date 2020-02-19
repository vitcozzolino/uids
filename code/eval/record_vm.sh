#!/bin/bash    
psrecord $2 --interval 0.5 --log $1UIDS --include-children &
psrecord $2 --interval 5 --log $1UIDS5 --include-children &
psrecord $3 --interval 0.5 --log $1Snort --include-children &
psrecord $3 --interval 5 --log $1Snort5 --include-children &
