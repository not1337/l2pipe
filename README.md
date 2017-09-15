l2pipe - pipe data via multiple ethernet interfaces using layer 2 only
======================================================================

l2pipe is an administrative tool that can be used e.g. for data backup and
restore or data transfer from an old system to a new system.

l2pipe is tuned for throughput speed and thus has no authentication or
encryption, thus it should be used only in secured networks.

l2pipe defaults to consuming RAM and CPU heavily though there are command
line options to reduce resource usage.

l2pipe needs direct ethernet connections, thus both systems involved must
be located on the same LAN (no bridges and no tagged VLANs). Only one
instance of l2pipe source and destination may run at the same time in
the same LAN.

l2pipe uses ethertype 0x88b5 which is reserved for local experimental use.

l2pipe has quite short timouts so it cannot be used via WLAN or other flakey
network connections.

Prerequisites:
--------------

- not to ancient Linux systems with a sufficiently recent kernel (>=4.11)
- gcc
- glibc with pthreads (standard)
- the lz4 library, e.g. from https://github.com/lz4/lz4

Compile:
--------

Edit the Makefile in case you need non standard include or library paths.
Then just start "make".

Usage and Command Line Options:
-------------------------------

l2pipe -s [-m] [-v] [-3|-2|-1|-0] [-a arg] dev ...

l2pipe -r [-m] [-v] dev ...

A maximum of 10 devices is supported.

 -s     sender mode
 -r     receiver mode
 -v     verbose errors
 -m     reduced memory footprint
 -3     use 3 parallel compressors (default 4)
 -2     use 2 parallel compressors (default 4)
 -1     use 1 compressor (default 4)
 -0     use no compressor (default 4 compressors)
 -a arg use destribution scheme across devices
        according to arg:
        arg=n[.n[.n[...]]]
        n=a numeric value from 1 to 10
        use first n as amount of large packets to
        queue for first device, use second n for
        for second device and so on...
        Default is one large packet per device.

Example:
--------

You need to backup a system. The backup media is a LTO-7 tape attached to
another system. Now, LTO-7 has a maximum throughput of 300MB/s for
uncompressible data and thus for the stated 2.5:1 compression a maximum
throughput of 750MB/s.

The system to be backed up unfortunately only has the usual 1Gbase-T
interface which typically has a maximum throughput of about 120MB/s.
Furthermore the ethernet interface is bonded with the WLAN interface
for failover.

Both systems are located relatively close to one another and both
systems do have USB3 ports.

Thus e.g. a PL27A1 based USB3 host to host cable can be used between
both systems which allows for an IP throughput of about 180MB/s.
Another option would be e.g. pairs of RTL8153 based USB3 to 1GBase-T
adapters used as direct point to point connections (slower but more
stable than the host to host cable variant).

So you either have to reconfigure networking and firewalling on both
systems and still have the TCP overhead which reduces throughput
and still too slow throughput speed for compressible data or you leave
the system configuration as is and use l2pipe which does on the fly
(de)compression for compressible data with a factor quite similar
to the tape compression ratio.

First, after connection the usb host to host cable is to enable the
interface on both systems, preferrably with jumbo frames:

ifconfig usb0 up mtu 9000

The backup command on the system with the tape device which need to be
started first would look like:

l2pipe -r eth0 usb0 | dd bs=262144 of=/dev/st0

The backup command on the source system would then look like:

tar -c -f - -b 512 / | l2pipe -s -a 1.2 eth0 usb0

The "-a 1.2" means that one data chunk is sent to the regular
ethernet interface and then two data chunks are sent to the
usb host to host cable based interface (the default is one data
chunk per interface). The resulting throughput of this configuration
is around 310MB/s for uncompressible data. Given the on the fly
(de)compression using the lz4 library a LTO-7 tape can then be written
to with the maximum tape speed.

If the system to be backed up cannot deliver data fast enough and
the tape device thus starts intensive shoe shining the bfr utility
supplied in the third party directory will help.

The bfr utility is an old utility and has to my knowledge no original
download location anymore. It is supplied as is, including a
patchset that needs to be applied prior to compiling bfr.
With this patchset bfr will allow for a multi GB stream buffer
on 64 bit systems.
