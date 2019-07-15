#!/bin/bash

swagger generate spec -o ./swaggerui/swagger.json # Requires go-swagger
docker build -t restful-clam .
docker stop restful-clam
docker run --rm -it -d -p 8080:8080 --name restful-clam -e NO_FRESHCLAM_ON_STARTUP=1 restful-clam
#docker run --rm -it -d -p 8080:8080 --name restful-clam restful-clam
docker logs restful-clam -f