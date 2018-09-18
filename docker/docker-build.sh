#!/bin/bash

docker-compose -f docker-compose-inventory.yml build
docker-compose -f docker-compose-location.yml build
docker-compose -f docker-compose-direction.yml build
