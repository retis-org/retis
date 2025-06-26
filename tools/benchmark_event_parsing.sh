#!/bin/bash

make bench -j$(nproc)

time_raw_1m=0
time_str_1m=0
iterations=20

for i in $(seq 1 $iterations); do
	elapsed=($(./target/release/retis benchmark events_parsing | cut -d' ' -f2 | tr '\n' ' '))
	time_raw_1m=$(expr $time_1m + ${elapsed[0]})
	time_str_1m=$(expr $time_1m + ${elapsed[1]})
done

echo "Did ${iterations} iterations:"
echo "Average 1M raw events parsing: $(expr $time_raw_1m / $iterations)µs"
echo "Average 1M str events parsing: $(expr $time_str_1m / $iterations)µs"
