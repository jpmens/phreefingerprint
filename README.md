# phreefingerprint

Create DNS TXT RR from PEM certificate for @dakami's Phreeload or for Extended DNSSEC Validator (see [my posting](http://blog.fupps.com/2011/02/16/ssl-certificate-validation-and-dnssec/) for what the latter does.

## Usage
	phreefingerprint [-t] domain certfile

certfile is a certificate in PEM format. E.g. to get your cert go to your SSL site:

	openssl s_client -connect amazon.de:443

copy and paste the cert from that output into `my.crt`. Then run

	./phreefingerprint mydomain my.crt
	mydomain IN TXT "v=key1 ha=sha1 h=561b9b3cc34cc2e6fa38a554be1f919ce4c8ce7a"

Most of this code is swiped from other SSL clients

I've added support for the (hopefully upcoming) TLSA as described in [dane](http://datatracker.ietf.org/wg/dane/). Use option '-t' to get that:


	./phreefingerprint  -t mydomain my.crt  
	mydomain IN TYPE65534 \# 22 ( 0101561b9b3cc34cc2e6fa38a554be1f919ce4c8ce7a )

There's an #ifdef in the code to enable TLSA RRtype.
