gipfl\\Protocol\\IP
===================

This is still an early prototype. Have a look at `examples/samples.php`, it
gives the following output:

```
Got a 151 byte (20 byte header, 131 byte payload) UDP packet from 192.0.2.6 to 239.255.255.250
  This packet has not been fragmented
  Fragmentation is allowed
  Time to live: 4

Got a 174 byte (20 byte header, 154 byte payload) TCP packet from 192.0.2.26 to 192.0.2.10
  This packet has not been fragmented
  Fragmentation is NOT allowed
  Time to live: 54

Got a 84 byte (20 byte header, 64 byte payload) ICMP packet from 192.0.2.10 to 8.8.8.8
  This packet has not been fragmented
  Fragmentation is NOT allowed
  Time to live: 64

Got a 1500 byte (20 byte header, 1480 byte payload) ICMP packet from 192.0.2.10 to 8.8.8.8
  This is the first fragment, more to come
  Fragmentation is allowed
  Time to live: 64

Got a 548 byte (20 byte header, 528 byte payload) ICMP packet from 192.0.2.10 to 8.8.8.8
  Fragment at offset 1480
  This is the last fragment of this packet
  Fragmentation is allowed
  Time to live: 64

```
