# ECNDMFHP p2p Chat

This repository contains the p2p chat client using the ECNDMFHP protocol defined in
the "Rechnernetze" (computer networks) course at HAW Hamburg.
This chat automatically establishes a p2p network accross an IP-network between clients.

# ECNDMFHP Protocol

ECNDMFHP is an acronym for:
- Enter request
- Connect
- New users
- Disconnect
- Message
- Failed
- Heartbeat
- Private

which describes the different package types the protocol consists of.
Every client has a list of all currently connected clients within the p2p-network.
If a new client joins, every client exchanges their clients with the new client, who
in turn exchanges their clients with the clients of the existing network, establishing /
extending the p2p-network.

## Docker
This chat client can be built as a docker container. Simply call make with the `docker` recipe:
`make docker` to create a docker image.
Docker is also used to test the application by spawning containers with the application and then
interacting with the containers through stdin / stdout.

## Usage

```
chat --sctp INTERVAL_TIME
    INTERVAL_TIME: Interval time for the sctp heartbeat.
                   Setting the interval time also enables SCTP as the
                   transmission protocol.
```

When in the chat, use `/connect IP_ADDRESS PORT` to connect to another client / network.
