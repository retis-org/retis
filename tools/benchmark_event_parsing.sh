#!/bin/bash

make bench -j$(nproc)

time_1m=0
iterations=20

for i in $(seq 1 $iterations); do
	elapsed=($(./target/release/retis benchmark events_parsing | cut -d' ' -f2 | tr '\n' ' '))
	time_1m=$(expr $time_1m + ${elapsed[0]})
done

echo "Did ${iterations} iterations:"
echo "Average 1M events parsing: $(expr $time_1m / $iterations)µs"
