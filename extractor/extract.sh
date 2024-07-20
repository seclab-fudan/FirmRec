#! /bin/bash

EXTRACTOR_DIR=$(dirname $(realpath $0))
DOCKER_IMAGE="my/binwalk"
EXTRACTOR_SCRIPT=${EXTRACTOR_DIR}/extractor.py

# check whether the docker image is available
if [[ "$(docker images -q $DOCKER_IMAGE 2> /dev/null)" == "" ]]; then
  # echo "Docker image $DOCKER_IMAGE not found."
  # echo "Build it with: docker build -t $DOCKER_IMAGE ."
  # exit 1
  USE_DOCKER=0
else
  USE_DOCKER=1
fi

# check whether the input file is provided
if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <input file> <output directory>"
  exit 1
fi

infile=$1
outdir=$2

# check whether the input file exists
if [[ ! -f "${infile}" ]]; then
  echo "Input file ${infile} not found"
  exit 1
fi

if [[ ! -d "${outdir}" ]]; then
  echo "Output directory ${outdir} not found, creating it"
  mkdir -p "${outdir}"
fi

# override 65535k docker default size with 1024MB (not tmpfs default for OSX compatibility)
mem=1048575k

indir=$(realpath $(dirname "${infile}"))
outdir=$(realpath "${outdir}")
infilebn=$(basename "${infile}")

if [[ $USE_DOCKER -eq 0 ]]; then
  fakeroot /usr/bin/python3 $EXTRACTOR_SCRIPT \
    -v -np \
    "${infile}" \
    "${outdir}"
else
  docker run --rm -t -i --tmpfs /tmp:rw,size=${mem} \
    -v "${indir}:/firmware-in:ro" \
    -v "${outdir}:/firmware-out" \
    "$DOCKER_IMAGE" \
    fakeroot python3 /home/appuser/extractor.py \
    -v -np \
    /firmware-in/"${infilebn}" \
    /firmware-out
fi
exit $?
