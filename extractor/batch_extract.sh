#!/bin/bash

SCRIPT_DIR=$(dirname $(realpath $0))

indir=$1
outdir=$2

if [[ ! -d "${indir}" ]]; then
    echo "Input directory ${indir} not found"
    exit 1
fi

if [[ ! -d "${outdir}" ]]; then
    echo "Output directory ${outdir} not found, creating it"
    mkdir -p "${outdir}"
fi

indir=$(realpath "${indir}")
outdir=$(realpath "${outdir}")

temp_script=$(mktemp)

for infile in "${indir}"/*; do
    infilebn=$(basename "${infile}")
    outfile="${outdir}/${infilebn}.tar"
    if [[ -f "${outfile}" ]]; then
        echo "Output file ${outfile} already exists, skipping"
        continue
    fi
    # "$SCRIPT_DIR/extract.sh" "${infile}" "${outdir}"
    echo \"$SCRIPT_DIR/extract.sh\" \"${infile}\" \"${outdir}\" >>$temp_script
done

cat $temp_script

# parallel -j 4 < $temp_script
