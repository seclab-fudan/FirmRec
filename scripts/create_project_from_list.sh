#!/bin/bash

if [[ $# != 1 ]]; then
    echo "Usage: $0 LIST"
    exit
fi


prefix=/home/iot/firmware/unpacked
create_project=$(dirname $0)/create_project.sh

list_file=$1
bindir=$list_file-ghidra

mkdir -p $bindir
while IFS= read -r line; do
    relative_path=$(realpath --relative-to="$prefix" "$line")
    
    vendor=$(echo $relative_path | cut -d'/' -f1)
    firmware=$(echo $relative_path | cut -d'/' -f2)
    binpath=$(echo $relative_path | cut -d'/' -f3-)
    binname="$vendor@@$firmware@@${binpath//\//@@}"
    # echo $binname
    cp $line "$bindir/$binname"
done < "$1"

$create_project $bindir
