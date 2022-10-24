# syntax=docker/dockerfile:1

FROM golang:1.19-alpine

RUN apk add --no-cache make

WORKDIR /ghanalyzer

ADD go.* /ghanalyzer/

RUN go mod download
RUN go env -w GO111MODULE=on

ADD . /ghanalyzer/

RUN make all

ENTRYPOINT [ "/ghanalyzer/bin/github-analyzer" ]
