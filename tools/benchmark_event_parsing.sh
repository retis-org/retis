#!/bin/bash

cargo build --release -F benchmark

time_first=0
time_1m=0
iterations=20

for i in $(seq 1 $iterations); do
	elapsed=($(./target/release/retis benchmark events_parsing | cut -d' ' -f2 | tr '\n' ' '))
	time_first=$(expr $time_first + ${elapsed[0]})
	time_1m=$(expr $time_1m + ${elapsed[1]})
done

echo "Did ${iterations} iterations:"
echo "Average first event parsing: $(expr $time_first / $iterations)µs"
echo "Average 1M events parsing: $(expr $time_1m / $iterations)µs"
