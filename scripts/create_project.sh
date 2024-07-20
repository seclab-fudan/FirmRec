#!/bin/bash

if [[ $# != 1 ]]; then
    echo "Usage: $0 [DIRECTORY_OF_BINS]"
    exit
fi

bin_dir=$1

CMD="/home/iot/Tools/ghidra_10.2.2_DEV/support/analyzeHeadless $bin_dir/.. $(basename $bin_dir)"
for bin in $(grep -rIL . $bin_dir)
do
    CMD+=" -import $bin"
done

$CMD