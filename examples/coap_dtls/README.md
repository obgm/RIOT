examples/coap_dtls
======================
This application shows libcoap and DTLS based on RIOT's POSIX socket
wrapper and the tinydtls package.

Usage
=====

Build, flash and start the application:
```
export BOARD=your_board
make
make flash
make term
```

The `term` make target starts a terminal emulator for your board. It
connects to a default port so you can interact with the shell, usually
that is `/dev/ttyUSB0`. If your port is named differently, the
`PORT=/dev/yourport` (not to be confused with the UDP port) variable can
be used to override this.


Example output
==============

The shell commands come with online help. Call `help` to see which commands
exist and what they do.

The coap_dtls example adds a new command `psk` to set the default
pre-shared key (PSK) for DTLS communication over CoAP. The command
takes a single string argument that will be set as PSK:


```
> psk secretPSK
```

Send a CoAP request with `coap get coaps://[2001:638:708:30c9:e005:35ff:fea1:df6a]/.well-known/core`:




You can get the IPv6 address of the destination by using the `ifconfig` command on the receiver:

```
2015-09-22 14:58:10,394 - INFO # ifconfig
2015-09-22 14:58:10,397 - INFO # Iface  6   HWaddr: 9e:06  Channel: 26  NID: 0x23  TX-Power: 0dBm  State: IDLE CSMA Retries: 4
2015-09-22 14:58:10,399 - INFO #            Long HWaddr: 36:32:48:33:46:d4:9e:06
2015-09-22 14:58:10,400 - INFO #            AUTOACK  CSMA  MTU:1280  6LO  IPHC
2015-09-22 14:58:10,402 - INFO #            Source address length: 8
2015-09-22 14:58:10,404 - INFO #            Link type: wireless
2015-09-22 14:58:10,407 - INFO #            inet6 addr: ff02::1/128  scope: local [multicast]
2015-09-22 14:58:10,415 - INFO #            inet6 addr: fe80::3432:4833:46d4:9e06/64  scope: local
2015-09-22 14:58:10,416 - INFO #
```


