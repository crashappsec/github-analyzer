FROM golang:1.19-alpine as build

RUN apk add --no-cache make

WORKDIR /ghanalyzer

ADD go.* /ghanalyzer/

RUN go mod download
RUN go env -w GO111MODULE=on

ADD . /ghanalyzer/

RUN make all

# ----------------------------------------------------------------------------

FROM alpine

COPY --from=build /ghanalyzer/bin/github-analyzer /bin/github-analyzer

ENTRYPOINT [ "/bin/github-analyzer" ]
