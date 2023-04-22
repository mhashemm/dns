FROM golang:1.20.3-alpine3.17

WORKDIR /app

COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /dns

EXPOSE 53/udp
EXPOSE 80

ENV UDP_PORT=53
ENV TCP_PORT=80

CMD ["/dns"]