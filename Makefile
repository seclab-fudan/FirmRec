.phony: help build start clean clean_dangling

help:
	@echo "make help - Show this help"
	@echo "make build - Build the container"
	@echo "make start - Run the container"
	@echo "make clean - Stop and remove the container"

start:
ifeq ($(shell docker ps -a -f name=firmrec --format '{{.Status}}' | wc -l), 0)
	@echo "Container not found, creating a new one..."
	@docker run -dt -v $(PWD)/inout:/root/inout:z --name firmrec firmrec
endif
ifeq ($(shell docker ps -f name=firmrec --format "{{.Status}}" | wc -l), 0)
	@echo "Starting container"
	@docker start firmrec
	@docker exec -it firmrec /bin/bash -c "echo Starting postgres && pg_ctlcluster 11 main start"
endif
	@docker exec -it firmrec /bin/bash

build: clean
	@docker build -t firmrec .

clean:
	@echo "Stopping and removing container..."
	@(docker stop firmrec && docker rm firmrec) || true >/dev/null
	@(docker rmi firmrec) || true >/dev/null

clean_dangling: clean
	@docker rmi $(docker images --filter "dangling=true" -q --no-trunc) 2>/dev/null || true
