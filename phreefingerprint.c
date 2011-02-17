/*
 * phreefingerprint
 * Create DNS TXT RR from PEM certificate for @dakami's Phreeload
 * by Jan-Piet Mens November 2010
 *
 * Usage: phreefingerprint domain certfile
 *
 *	certfile is a certificate in PEM format. E.g. to get
 *	your cert go to your SSL site:
 *
 *	$ openssl s_client -connect amazon.de:443
 *
 *	copy and paste the cert from that output into `my.crt'.
 *
 * run
 *
 *	$ ./phreefingerprint mydomain my.crt
 *	mydomain IN TXT "v=key1 ha=sha1 h=5deb92ac5e5868322ae67a42c1582886d588dab2"
 *
 * Most of this code is swiped from other SSL clients
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#define FORMAT_ASN1     1
#define FORMAT_TEXT     2
#define FORMAT_PEM      3
#define FORMAT_PKCS12   5
#define FORMAT_SMIME    6

static X509 *load_cert(BIO *err, char *file, int format);
static char *strtolower(const char *s);

int main(int argc, char **argv)
{
	BIO *STDout, *bio_err;
	X509 *x;
	char *infile, *domain, *hash;
	int informat = FORMAT_PEM, j, c, tlsa = 0;
	const EVP_MD *digest = EVP_sha1();
	unsigned int n;
	unsigned char md[EVP_MAX_MD_SIZE];

	while ((c = getopt(argc, argv, "t")) != EOF) {
		switch (c) {
			case 't':
				tlsa = 1;
				break;
			default:
				fprintf(stderr, "Usage: %s [-t] domain PEM\n", *argv);
				exit(2);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s [-t] domain certfile\n", *argv);
		exit(2);
	}

	domain = argv[0];
	infile = argv[1];
  
	STDout = BIO_new_fp(stdout,BIO_NOCLOSE);
	bio_err = BIO_new_fp(stderr,BIO_NOCLOSE);

	x = load_cert(bio_err,infile,informat);


	if (!X509_digest(x,digest,md,&n))
	{
		BIO_printf(bio_err,"out of memory\n");
		BIO_free(bio_err);
		exit(3);
	}


	hash = strtolower(OBJ_nid2sn(EVP_MD_type(digest)));
	if (tlsa == 0) {
		/*
		 * Print out a DNS TXT RR for Phreeload.
		 * 	domain  IN TXT "v=key1 ha=sha1 h=5e0905b0eafd35d59f1b178727d4eaadd06c415d"
		 */
	
		BIO_printf(STDout,"%s IN TXT \"v=key1 ha=", domain);
	
		if (hash) {
			BIO_printf(STDout,"%s ", hash);
			free(hash);
		} else {
			BIO_printf(STDout,"unknown ");
		}
	
		BIO_printf(STDout, "h=");
		for (j = 0; j < n; j++) {
			BIO_printf(STDout, "%02x", md[j]);
		}
		BIO_printf(STDout, "\"\n");
	} else {

		/* Print as TLSA
		 * (http://datatracker.ietf.org/doc/draft-ietf-dane-protocol/?include_text=1)
		 */

		int htype = 0;
		int certtype = 1;		// Hash of end-entity cert
		int len;

		if (!strcmp(hash, "sha1")) {
			htype = 1;
		} else if (!strcmp(hash, "sha256")) {
			htype = 2;
		} else {
			fprintf(stderr, "Can't (yet) handle hash type %s\n", hash);
			exit(3);
		}

#ifdef DRAFTPASSED
		
		BIO_printf(STDout,"%s IN TLSA ( %d %d ", domain, certtype, htype);
		for (j = 0; j < n; j++) {
			BIO_printf(STDout, "%02x", md[j]);
		}
		BIO_printf(STDout," )\n");
#else

		len = n + 2; 	// length of hash + certype + hashtype

		BIO_printf(STDout,"%s IN TYPE65534 \\# %d ( %02X%02X", domain, len, certtype, htype);
		for (j = 0; j < n; j++) {
			BIO_printf(STDout, "%02x", md[j]);
		}
		BIO_printf(STDout," )\n");
#endif

	}

	return (0);
}

static X509 *load_cert(BIO *err, char *file, int format)
{
	ASN1_HEADER *ah=NULL;
	BUF_MEM *buf=NULL;
	X509 *x=NULL;
	BIO *cert;

	if ((cert=BIO_new(BIO_s_file())) == NULL) {
		goto end;
	}

	if (file == NULL) {
		BIO_set_fp(cert,stdin,BIO_NOCLOSE);
	}
	else {
		if (BIO_read_filename(cert,file) <= 0) {
			perror(file);
			goto end;
		}
	}

	if 	(format == FORMAT_ASN1)
		x=d2i_X509_bio(cert,NULL);
	else if (format == FORMAT_PEM)
		x=PEM_read_bio_X509_AUX(cert,NULL,NULL,NULL);
	else if (format == FORMAT_PKCS12)
		{
		PKCS12 *p12 = d2i_PKCS12_bio(cert, NULL);

		PKCS12_parse(p12, NULL, NULL, &x, NULL);
		PKCS12_free(p12);
		p12 = NULL;
		}
	else	{
		fprintf(stderr, "Crypt::OpenSSL::SMIME: bad input format specified for input cert\n");
		goto end;
		}
end:
	if (x == NULL)
		{
		fprintf(stderr, "Crypt::OpenSSL::SMIME: unable to load certificate\n");
		}
	if (ah != NULL) ASN1_HEADER_free(ah);
	if (cert != NULL) BIO_free(cert);
	if (buf != NULL) BUF_MEM_free(buf);
	return(x);
}

static char *strtolower(const char *s)
{
	char *p = strdup(s);

	if (p) {
		char *bp = p;

		while (bp && *bp) {
			if (isupper(*bp))
				*bp = tolower(*bp);
			bp++;
		}
	}
	return (p);
}
