FROM firmrec-base

# Copy files

RUN rm -rf ./firmrec ./firmlib ./scripts ./tests /extractor ./config.yaml

COPY firmrec ./firmrec
COPY firmlib ./firmlib
COPY scripts ./scripts
COPY extractor ./extractor
COPY config.yaml ./config.yaml

ENTRYPOINT ["/bin/bash"]