## yggdrasil-zig

A port to [zig](https://ziglang.org/learn/) of the
[yggdrasil-network](https://github.com/yggdrasil-network/yggdrasil-go) go
canonical implementation.

Still in heavy development.

## High level view of how to join the yggdrasil net (leaf node)

We generate (or load) a Ed25519 pair of keys. Derivate our IPv6 address from them. 
Now we can create a tun device and associate the IPv6 to it. 

Now we need to create a tun device and associate the IPv6 address. 

Next, we can open a socket (tcp to keep it simple) against a node that is
already part of the YGN. In our case we will have the zig implementation (Zig
Node - ZN) and another node that will run the canonical go implementation (GO
node - GN).

In that socket, we follow the handskake:

  1. Connect TCP
  2. Send handshake (starts with "meta")
  3. Receive handshake (starts with "meta")
  4. Switch to data mode
  5. All subsequent packets are network data (start with session type - first byte is 0x01).

When we get data from the Gnode (read from the tcp socket), we have to remove
the 01 and inject the ipv6 packet into the OS stack which will deliver it to
whatever application the data belongs to.

When a proccess sends data to a ygg node, we will get it as we read from the
tun device. That is a IPv6 packet that we have to send over the tcp socket
setting the first byte as 0x01.

## TODO

```
 - [x] 1. generate Ed25519 key generate and load
 - [x] 2. hex encoding of the keys
 - [x] 3. IPv6 address derivation (look at yggdrasil code)
 - [x] 4. create tun device (set ipv6 address)
 - [ ] 5. associate my ipv6 address to the tun device.
 - [ ] 6. Implement the handshake with G.
      - [ ] a. method to prepare structure.
      - [ ] b. write code to send handshake
      - [ ] c. read response.
 7. read(tun): send them over the tcp connection to G.
 8. read(tcp connection with G): write them to the tun device.
 Milestone: At this point I should have a functioning Yggdrasil leaf node.
```

