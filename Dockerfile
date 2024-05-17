FROM golang AS builder

ARG GOOS
ARG GOARCH

COPY ./src /src

WORKDIR /src

RUN go mod init github.com/skeeve/go-decrypt-dbvis \
 && go mod tidy \
 && go build ./cmd/decrypt-dbvis \
 && env

 FROM scratch AS exporter

 COPY --from=builder /src/decrypt-dbvis ./
