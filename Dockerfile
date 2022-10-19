# syntax=docker/dockerfile:1

FROM golang:1.19-alpine

WORKDIR /ghanalyzer

ADD . /ghanalyzer

RUN go mod download
RUN go env -w GO111MODULE=on

RUN mkdir -p bin && go build -o bin/github-analyzer cmd/github-analyzer/main.go

ENTRYPOINT [ "/ghanalyzer/bin/github-analyzer" ]
