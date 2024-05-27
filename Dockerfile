FROM alpine as build-env

RUN apk add --no-cache build-base lksctp-tools-dev

COPY . /p2pchat

WORKDIR /p2pchat

RUN make clean && make debug

FROM alpine

COPY --from=build-env /p2pchat/build/chat /p2pchat/chat
WORKDIR /p2pchat

CMD ["/p2pchat/chat"]
