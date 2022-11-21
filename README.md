# UFTP - Encrypted UDP based FTP with multicast
(Cloned from https://uftp-multicast.sourceforge.net)

UFTP is an encrypted multicast file transfer program, designed to securely,
reliably, and efficiently transfer files to multiple receivers simultaneously.
This is useful for distributing large files to a large number of receivers,
and is especially useful for data distribution over a satellite link (with two
way communication), where the inherent delay makes any TCP based communication
highly inefficient.  The multicast encryption scheme is based on TLS with
extensions to allow multiple receivers to share a common key.

UFTP also has the capability to communicate over disjoint networks separated
by one or more firewalls (NAT traversal) and without full end-to-end multicast
capability (multicast tunneling) through the use of a UFTP proxy server. 
These proxies also provide scalability by aggregating responses from a group
of receivers.

## Building

UNIX-like systems require GNU make and a C compiler such as GCC or
equivalent.  Windows systems require Visual Studio Community 2015 or later.

Non-Windows systems require OpenSSL to be installed if encryption support is
enabled.  On Linux, Solaris, and BSD systems (including MacOSX), this should
be included with the OS.


To compile for UNIX-like systems, including MacOSX:
`make [ OPENSSL={install directory for OpenSSL} ] [ NO_ENCRYPTION=1 ]`

To compile for Windows (from a Visual Studio command prompt):
`nmake -f makefile.mak [ OPENSSL={install directory for OpenSSL} ] [ NO_ENCRYPTION=1 ]`

By default, Visual Studio compiles a 32-bit executable.  To compile in 64-bit
mode, first cd to the VC subdirectory under the Visual Studio install directory.
Then run the following command:

`vcvarsall amd64`

The OPENSSL parameter to make should only need to be specified if OpenSSL is
installed in a non-standard location, or on systems where it isn't
preinstalled.

The NO_ENCRYPTION flag compiles with no encryption support.  This can be
useful in embedded environments that don't need encryption and want to
keep the size of the executable down, and for use in a Windows service
that doesn't require encryption.


To install for UNIX-like systems, including MacOSX:
`make [ DESTDIR={install directory} ] install`

The DESTDIR parameter allows installing into a fake root directory, which
can be useful for packaging utilities such as rpm.


## Tuning

If you find that clients can't receive data fast enough, or if servers
communicating with several hundred clients can't handle the flood of
STATUS messages that come in, you can increase the UDP send/receive buffer
size to help with this.  This is set using the -B option on server, 
client, or proxy.  However, many operating systems impose a maximum value
of 256K (262144).  This limit can be increased, although the method is OS
specific.  Here are a few common ones:

Solaris: `ndd -set /dev/udp udp_max_buf {value}`

Linux: `sysctl -w net.core.rmem_max={value}`
       `sysctl -w net.core.wmem_max={value}`

MacOSX / FreeBSD: `sysctl -w kern.ipc.maxsockbuf={value}`
(The actual maximum you can use is 8/9 of this value)

While Windows does not have this limitation, it does throttle back UDP
datagrams larger that 1024 bytes by default (a UFTP packet is 1472 bytes by
default).  This is most commonly seen when attempting to move data at 100
Mbps or more.  You can change this by adding/modifying the following registry
value:

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters\FastSendDatagramThreshold

Set this DWORD value to 1500 and reboot, and it should take care of the issue.

If you're making use of the DSCP/TOS byte in the IP header, this can be
modified via the -Q option to the server, client, or proxy.  Setting this byte
is not currently supported in Windows.

The TOS byte also contains the ECN bits, which are used by the TFMCC 
congestion control scheme, so restrictions on the TOS byte also affect the
sender support for ECN.

## Upgrading from 4.x to 5.x

Key changes from 4.x to 5.x:

- The use of source specific multicast is not automatically turned on when
  a client or proxy uses a server list file.  It is now enabled separately
  with the -o option on the client and the proxy.
- Under 4.x, a client proxy would substitute its own keys in place of the
  server's when forwarding an ANNOUNCE.  Now the ANNOUNCE is forwarded
  unchanged and the proxy sends a PROXY_KEY with its own keys.
- Because of the key changes, clients are now fully aware of proxies.  If a
  client talks to a server through a proxy, the server must be listed in the
  server list file along with the ID of proxy it communicates through.
- The server list file no longer contains the key fingerprint of the proxy
  that the server goes through but the fingerprint of the server itself.
  Fingerprints for proxies are now specified in a separate file.

The client and proxy support both the version 4 and version 5 protocols.
When upgrading from version 4.x to version 5.x, the following steps should
be taken:

If you use encrypted sessions and are running version 4.10.1 or earlier,
the server should first be upgraded to version 4.10.2.  Also, since 5.x
versions have a more restricted set of encryption parameters, the server's
parameters should be updated to match.  Specifically, it must use an ECDH key
exchange mode, a GCM or CCM mode symmetric cypher, and SHA-256, SHA-384,
or SHA-512 for the hash.

If proxies are not in use, upgrade clients one at a time to 5.x, then upgrade
the server to 5.x once all clients are upgraded.

If proxies are in use and you want to perform a rolling upgrade:

- Upgrade server proxies to 5.x one at a time.
- Upgrade client proxies to 5.x one at a time.
- Upgrade response proxies to 5.x one at a time.
- Upgrade clients to 5.x one at a time.  If the client is using client 
  proxies, they must be listed in the server list file specified by -S for
  each server that uses a proxy.  Also, if your server list file contains key
  fingerprints, you will need to add an additional entry for each server.
  Under 4.x a server entry contains the fingerprint of the proxy used by the
  server, while under 5.x the entry contains the server's fingerprint
  with the proxy's fingerprint in a separate file.  These servers will need
  to be assigned a new ID when upgrading so that clients can have two server
  list entries for the same server: one with the current ID running 4.x and the
  proxy's fingerprint, and one with the new ID running 5.x with the server's
  fingerprint.
- Upgrade server to 5.x.
