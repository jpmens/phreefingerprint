# phreefingerprint

Create DNS TXT RR from PEM certificate for @dakami's Phreeload.
November 2010

## Usage
	phreefingerprint domain certfile

certfile is a certificate in PEM format. E.g. to get your cert go to your SSL site:

	openssl s_client -connect amazon.de:443

copy and paste the cert from that output into `my.crt`. Then run

	./phreefingerprint mydomain my.crt
	mydomain IN TXT "v=key1 ha=sha1 h=5deb92ac5e5868322ae67a42c1582886d588dab2"

Most of this code is swiped from other SSL clients
