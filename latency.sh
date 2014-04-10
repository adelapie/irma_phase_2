#!/bin/sh

cat $1 | grep "ms\." | awk '{ sum += $3 } END { print sum }'
