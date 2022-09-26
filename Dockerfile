# syntax=docker/dockerfile:1 

FROM golang:1.19-alpine 

WORKDIR /auditor

ADD . /auditor

RUN go mod download
RUN go env -w GO111MODULE=on

RUN mkdir -p bin && go build -o bin/auditor cmd/main/main.go

ENTRYPOINT [ "/auditor/bin/auditor" ]
