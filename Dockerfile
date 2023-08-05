FROM golang:1.20.7 as build

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/deblockerd ./cmd/deblockerd

FROM debian:bookworm-slim

COPY --from=build /go/bin/deblockerd /

ENTRYPOINT ["/deblockerd"]
