#!/bin/bash

# Array of URLs to test
declare -a urls=(
"http://localhost:5001/domain-info?domain=sparv.ai"
"http://localhost:5001/domain-info?domain=dotkeeper.com"
"http://localhost:5001/domain-info?domain=bubbleroomsweden.com"
"http://localhost:5001/domain-info?domain=bubbleroom.ee"
"http://localhost:5001/domain-info?domain=bubbleroom.uk"
"http://localhost:5001/domain-info?domain=bubbelroom.sk"
"http://localhost:5001/domain-info?domain=bubbleroom.se"
"http://localhost:5001/domain-info?domain=bubbleroom.ru"
"http://localhost:5001/domain-info?domain=bubbleroom.pl"
)

# Loop through the array and execute curl for each URL
for url in "${urls[@]}"
do
   curl "$url" & 
done

# Wait for all background jobs to finish
wait
echo "All requests completed."
