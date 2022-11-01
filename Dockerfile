FROM golang:1.19.2 as build

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/deblockerd ./cmd/deblockerd

FROM debian:bullseye-backports

COPY --from=build /go/bin/deblockerd /

ENTRYPOINT ["/deblockerd"]
