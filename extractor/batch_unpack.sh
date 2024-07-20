#! /bin/bash

if [[ $# != 2 ]]; then
    echo "Usage: $0 INPUT_DIR outdir_DIR"
    exit
fi

UNPACK_LOCAL="$(dirname $0)/unpack.sh"

inpdir=$1
outdir=$2

mkdir -p $outdir

for filepath in $inpdir/*.tar; do
    targetdir="$outdir/$(basename ${filepath/.tar//})"

    $UNPACK_LOCAL $filepath $targetdir
done