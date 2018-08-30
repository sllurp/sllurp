#!/bin/bash

docker build -t pom_inventory -f Dockerfile.inventory .
docker build -t pom_location -f Dockerfile.location .
