#! /bin/bash

# Note: This script is intended to be used for unpacking non-malicious tar

if [[ $# != 2 ]]; then
    echo "Usage: $0 INPUT_TAR OUTPUT_DIR"
    exit
fi

inptar=$1
outdir=$2

mkdir -p $outdir

filename=$(basename $inptar)
targetdir="$outdir"

if [ -d $targetdir ]; then
    # if [ "$(ls -A $targetdir)" ]; then
    #     exit 0
	# else
    #     rm -rf $targetdir
    # fi
    # force remove
    rm -rf $targetdir
fi
mkdir -p "$targetdir"

# MacOS does not support fakechroot
if [[ $(uname) == "Darwin" ]]; then
    tar --no-same-permissions -x -f "$inptar" -C "$targetdir"
    chmod -R 755 "$targetdir"
else
    ln -s $(which tar) $targetdir/
    ln -s $(which ls) $targetdir/
    ln -s $(which rm) $targetdir/
    ln -s $(which chmod) $targetdir/
    ln -s $(realpath $inptar) $targetdir/archive.tar

    fakechroot chroot $targetdir /tar --no-same-permissions -x -f "./archive.tar"
    fakechroot chroot $targetdir /chmod -R 755 .
    # fakechroot chroot $targetdir /ls

    # tar xf $filepath
    find ${targetdir} -type l -delete
fi
