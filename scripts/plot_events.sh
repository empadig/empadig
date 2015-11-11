#!/bin/bash

input=$1
output=$2

echo "set terminal png transparent nocrop enhanced size 1280,1024 font \"arial,8\" ; \
set output \"$output\"; \
set title \"Impact over Time\"; \
set xdata time; \
set timefmt \"%Y-%m-%d %H:%M:%S\"; \
set xtics format \"%m %d %H:%M\"; \
rgb(r,g,b) = 65536 * int(r) + 256 * int(g) + int(b); \
plot \"$input\" using 5:7:(rgb(\$8,\$9,\$10)) with points pt 7 ps 2 lc rgb variable \
\
" | gnuplot

# set these ranges to cut the time interval
#set xrange [\"2015-05-13 07:00:00\":\"2015-05-13 13:00:00\"]; \ 
#set yrange [0:250]; \ 

