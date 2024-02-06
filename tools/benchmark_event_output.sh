#!/bin/bash

make bench V=1

time_single_single=0
time_single_multi=0
time_single_json=0
time_series_single=0
time_series_multi=0
time_series_json=0

iterations=20

for i in $(seq 1 $iterations); do
	elapsed=($(./target/release/retis benchmark events_output | cut -d' ' -f2 | tr '\n' ' '))
	time_single_single=$(expr $time_single_single + ${elapsed[0]})
	time_single_multi=$(expr $time_single_multi + ${elapsed[1]})
	time_single_json=$(expr $time_single_json + ${elapsed[2]})
	time_series_single=$(expr $time_series_single + ${elapsed[3]})
	time_series_multi=$(expr $time_series_multi + ${elapsed[4]})
	time_series_json=$(expr $time_series_json + ${elapsed[5]})
done

echo "Did ${iterations} iterations:"
echo
echo "1M_time_single_single: $(expr $time_single_single / $iterations)µs"
echo "1M_time_single_multi: $(expr $time_single_multi / $iterations)µs"
echo "1M_time_single_json: $(expr $time_single_json / $iterations)µs"
echo
echo "1M_time_series_single: $(expr $time_series_single / $iterations)µs"
echo "1M_time_series_multi: $(expr $time_series_multi / $iterations)µs"
echo "1M_time_series_json: $(expr $time_series_json / $iterations)µs"
