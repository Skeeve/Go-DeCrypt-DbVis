FROM golang AS builder

ARG GOOS
ARG GOARCH

COPY ./src /src

WORKDIR /src

RUN go mod init decrypt-dbvis \
 && go mod tidy \
 && go build decrypt-dbvis \
 && env

 FROM scratch AS exporter

 COPY --from=builder /src/decrypt-dbvis ./
 