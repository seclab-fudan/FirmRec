FROM cincan/binwalk:latest

WORKDIR /home/appuser

USER root

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt upgrade -y
RUN apt-get install -y fakeroot python3-dev python3-pip

COPY extractor.py /home/appuser/
WORKDIR /home/appuser/

# USER appuser
ENTRYPOINT ["/bin/bash"]