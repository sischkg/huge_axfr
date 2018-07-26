# huge_axfr

## Overview

`huge_axfr` is primary DNS server which generate huge or infinit zone and transfer it to secondary servers.
This tool is useful for testing following operational notifications from ISC.
 * Operational Notification: A party that is allowed control over zone data can overwhelm a server by transferring huge quantities of data.(https://kb.isc.org/article/AA-01390).
 * Operational Notification: Extremely large zone transfers can result in corrupted journal files or server process termination(https://kb.isc.org/article/AA-01627).

## Quick Start

Install CentOS 7.5.

Install packages for compiling huge_axfr_server.

```
# yum install epel-release
# yum install gcc-c++ cmake boost-devel wget perl cmake git gtest-devel

# wget https://www.openssl.org/source/openssl-1.1.0h.tar.gz
# tar xzf openssl-1.1.0h.tar.gz
# cd openssl-1.1.0h
# ./config
# make
# make install
# echo /usr/local/lib64 > /etc/ld.so.conf.d/local.conf
# ldconfig

# wget https://cmake.org/files/v3.10/cmake-3.10.0-Linux-x86_64.sh
# sh cmake-3.10.0-Linux-x86_64.sh --skip-license --prefix=/usr/local
```

Compile huge_axfr.

```
$ git clone https://github.com/sischkg/huge_axfr.git
$ cd huge_axfr
$  OPENSSL_ROOT_DIR=/usr/local/ssl cmake .
$ make
```

Start axfr_server which generates infinit size zone data.

```
$ ./bin/axfr_server --port 1053
```

Receive zone via AXFR.

```
$ dig @127.0.0.1 -p 1053 example.com axfr

; <<>> DiG 9.12.2rc2 <<>> @10.201.8.34 -p 1053 example.com axfr
; (1 server found)
;; global options: +cmd
example.com.            600     IN      SOA     mname.example.com. ns.example.com. 1532571359 360000 10000 3600000 3600
example.com.            600     IN      NS      www.example.com.
www.example.com.        600     IN      A       192.168.0.1
5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com. 600 IN A 192.168.0.1
0000000000000000.5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com. 600 IN CNAME 5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com.
0000000000000001.5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com. 600 IN CNAME 5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com.
0000000000000002.5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com. 600 IN CNAME 5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com.
0000000000000003.5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com. 600 IN CNAME 5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com.
0000000000000004.5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com. 600 IN CNAME 5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com.
```


Start axfr_server which generates finit size zone data.

```
$ ./bin/axfr_server --port 1053 -c 1000
```

Receive zone via AXFR.

```
$ dig @127.0.0.1 -p 1053 example.com axfr

; <<>> DiG 9.12.2rc2 <<>> @10.201.8.34 -p 1053 example.com axfr
; (1 server found)
;; global options: +cmd
example.com.            600     IN      SOA     mname.example.com. ns.example.com. 1532571359 360000 10000 3600000 3600
example.com.            600     IN      NS      www.example.com.
www.example.com.        600     IN      A       192.168.0.1
5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com. 600 IN A 192.168.0.1
0000000000000000.5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com. 600 IN CNAME 5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com.
0000000000000001.5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com. 600 IN CNAME 5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com.
0000000000000002.5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com. 600 IN CNAME 5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com.
0000000000000003.5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com. 600 IN CNAME 5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com.
0000000000000004.5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com. 600 IN CNAME 5b592edf.123456789022345678903234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.123456789022345678903234567890423456789052345678906234567890.example.com.
```

Send NOTIFY MESSAGE to slave server.

```
$ ./bin/notify -t 10.201.8.32 -z example.com
ID: 1234
Query/Response: Response
OpCode: 4
Authoritative Answer: 1
Truncation: 0
Recursion Desired: 0
Recursion Available: 0
Checking Disabled: 0
Response Code: NoError   No Error
Query: example.com. IN SOA
```
