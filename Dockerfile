# Build image
FROM golang:alpine AS builder

COPY main.go /go
WORKDIR /go

# Fetch dependencies, build binary
RUN apk update && apk add --no-cache git
RUN go get github.com/gorilla/mux
RUN go build -ldflags="-w -s" -o /go/bin/restful-clam

# Runtime image
FROM alpine:latest

RUN date +%Y%m%d > /build.txt

# Default environment variables
ENV API_PORT 8080
ENV CONF_DIR /restful-clam
ENV DATA_DIR /data
ENV USERNAME restful-clam

RUN adduser -D -g '' restful-clam

RUN apk update && apk add --no-cache bash clamav openrc && rm -f /var/cache/apk/*

COPY --from=builder /go/bin/restful-clam /go/bin/restful-clam
COPY entrypoint.sh /
COPY swaggerui/ /static/swaggerui
COPY clamav/clamd.conf /etc/clamav/clamd.conf
COPY eicar.txt /tmp/eicar.txt

RUN mkdir -p $DATA_DIR/files
RUN mkdir -p $DATA_DIR/metadata
RUN chown -R $USERNAME $DATA_DIR
RUN chown -R $USERNAME /var/log
RUN chown -R $USERNAME /var/lib/clamav

EXPOSE $API_PORT

WORKDIR $CONF_DIR

USER $USERNAME

ENTRYPOINT ["/entrypoint.sh"]
