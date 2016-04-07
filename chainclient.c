/*
 * chainclient.c
 * Work-in-Progress ...
 * Program to send and process proposed TLS DNSSEC chain extension.
 * Falls back to PKIX authentication if no chain response from server.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>


#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>
#include <getdns/getdns_ext_libevent.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "utils.h"
#include "starttls.h"


#define MYBUFSIZE 2048


/*
 * Enumerated Types and Global variables
 */

enum AUTH_MODE { 
    MODE_BOTH=0, 
    MODE_DANE, 
    MODE_PKIX 
};

int debug = 0;
enum AUTH_MODE auth_mode = MODE_BOTH;
char *CAfile = NULL;
char *service_name = NULL;

/*
 * DNSSEC Authentication Chain TLS extension type value etc
 */

#define DNSSEC_CHAIN_EXT_TYPE 53

int dnssec_chain = 1;

/*
 * usage(): Print usage string and exit.
 */

void print_usage(const char *progname)
{
    fprintf(stdout, "\nUsage: %s [options] <hostname> <portnumber>\n\n"
            "       -h:             print this help message\n"
            "       -d:             debug mode\n"
	    "       -n <name>:      service name\n"
	    "       -c <cafile>:    CA file\n"
            "       -m <dane|pkix>: dane or pkix mode\n"
	    "                       (default is dane & fallback to pkix)\n"
	    "       -s <app>:       use starttls with specified application\n"
	    "                       ('smtp', 'xmpp-client', 'xmpp-server')\n"
	    "\n",
	    progname);
    exit(1);
}


/*
 * parse_options()
 */

int parse_options(const char *progname, int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "hdn:c:m:s:")) != -1) {
        switch(opt) {
        case 'h': print_usage(progname); break;
        case 'd': debug = 1; break;
	case 'n':
	    service_name = optarg; break;
	case 'c':
	    CAfile = optarg; break;
        case 'm': 
	    if (strcmp(optarg, "dane") == 0)
		auth_mode = MODE_DANE;
	    else if (strcmp(optarg, "pkix") == 0)
		auth_mode = MODE_PKIX;
	    else
		print_usage(progname);
	    break;
	case 's': 
	    if (strcmp(optarg, "smtp") == 0)
	        starttls = STARTTLS_SMTP;
	    else if (strcmp(optarg, "xmpp-client") == 0)
		starttls = STARTTLS_XMPP_CLIENT;
	    else if (strcmp(optarg, "xmpp-server") == 0)
		starttls = STARTTLS_XMPP_SERVER;
	    else {
		fprintf(stderr, "Unsupported STARTTLS application: %s.\n",
			optarg);
		print_usage(progname);
	    }
	    break;
        default:
            print_usage(progname);
        }
    }
    return optind;
}


/*
 * print_cert_chain()
 * Print contents of given certificate chain.
 * Only DN common names of each cert + subjectaltname DNS names of end entity.
 */

void print_cert_chain(STACK_OF(X509) *chain)
{
    int i, rc;
    char buffer[1024];
    STACK_OF(GENERAL_NAME) *subjectaltnames = NULL;

    if (chain == NULL) {
	fprintf(stdout, "No Certificate Chain.");
	return;
    }

    for (i = 0; i < sk_X509_num(chain); i++) {
	rc = X509_NAME_get_text_by_NID(X509_get_subject_name(sk_X509_value(chain, i)),
				  NID_commonName, buffer, sizeof buffer);
	fprintf(stdout, "%2d Subject CN: %s\n", i, (rc >=0 ? buffer: "(None)"));
	rc = X509_NAME_get_text_by_NID(X509_get_issuer_name(sk_X509_value(chain, i)),
				  NID_commonName, buffer, sizeof buffer);
	fprintf(stdout, "   Issuer  CN: %s\n", (rc >= 0 ? buffer: "(None)"));
    }

    subjectaltnames = X509_get_ext_d2i(sk_X509_value(chain, 0),
                                       NID_subject_alt_name, NULL, NULL);
    if (subjectaltnames) {
        int san_count = sk_GENERAL_NAME_num(subjectaltnames);
        for (i = 0; i < san_count; i++) {
            const GENERAL_NAME *name = sk_GENERAL_NAME_value(subjectaltnames, i);
            if (name->type == GEN_DNS) {
                char *dns_name = (char *) ASN1_STRING_data(name->d.dNSName);
                fprintf(stdout, " SAN dNSName: %s\n", dns_name);
            }
        }
    }

    /* TODO: how to free stack of certs? */
    return;
}

/*
 * print_peer_cert_chain()
 * Note: this prints the certificate chain presented by the server
 * in its Certificate handshake message, not the certificate chain
 * that was used to validate the server.
 */

void print_peer_cert_chain(SSL *ssl)
{
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
    fprintf(stdout, "Peer Certificate chain:\n");
    print_cert_chain(chain);
    return;
}


/*
 * print_validated_chain()
 * Prints the verified certificate chain of the peer including the peer's 
 * end entity certificate, using SSL_get0_verified_chain(). Must be called
 * after a session has been successfully established. If peer verification
 * was not successful (as indicated by SSL_get_verify_result() not
 * returning X509_V_OK) the chain may be incomplete or invalid.
 */

void print_validated_chain(SSL *ssl)
{
    STACK_OF(X509) *chain = SSL_get0_verified_chain(ssl);
    fprintf(stdout, "Validated Certificate chain:\n");
    print_cert_chain(chain);
    return;
}


/*
 * dnssec_chain_parse_cb()
 * This routine will parse a dnssec_chain extension from the server,
 * authenticate it with DNSSEC, and then authenticate the server's 
 * certificate with the validated TLSA record set from the chain.
 *
 */

#define UNUSED_PARAM(x) ((void) (x))

static int dnssec_chain_parse_cb(SSL *ssl, unsigned int ext_type,
				 const unsigned char *ext_data, size_t ext_len,
				 int *al, void *arg)
{
    char *cp;
    getdns_list *to_validate_rrs = getdns_list_create();
    getdns_list *support_rrs = getdns_list_create();
    getdns_list *append_to = to_validate_rrs;
    getdns_dict *rr_dict;
    getdns_return_t rc;
    size_t buf_len, n_rrs, i;
    uint32_t rrtype, usage, selector, mtype;
    getdns_bindata *rrname = NULL, *cert_assoc_data;
    char *fqdn;
    getdns_list *trust_anchors;
    getdns_return_t dnssec_status;
    int ssl_rc;
    const char *hostname = (const char *)arg;

    UNUSED_PARAM(ssl);
    UNUSED_PARAM(al);
    UNUSED_PARAM(arg);

    if (debug) {
	fprintf(stdout, "Received DNSSEC chain extension (%d).\n"
		"Extension data length = %zu octets.\n", ext_type, ext_len);
	fprintf(stdout, "Data = %s\n", 
		(cp = bin2hexstring(ext_data, ext_len)));
	free(cp);
    }

    /* Parse the authentication chain */
    i = n_rrs = 0;
    buf_len = ext_len;
    while (buf_len > 0) {
	rc = getdns_wire2rr_dict_scan(&ext_data, &buf_len, &rr_dict);
	if (rc)
	    break;
	if ((rc = getdns_dict_get_bindata(rr_dict, "/name", &rrname))) {
	    fprintf(stderr, "FAIL: getting rrname: %s\n",
		    getdns_get_errorstr_by_id(rc));
	    break;
	}
	getdns_convert_dns_name_to_fqdn(rrname, &fqdn);
	if ((rc = getdns_dict_get_int(rr_dict, "/type", &rrtype))) {
	    fprintf(stderr, "FAIL: getting rrtype: %s\n",
		    getdns_get_errorstr_by_id(rc));
	    break;
	}
        if (append_to == to_validate_rrs) {
	    if (rrtype == GETDNS_RRTYPE_RRSIG)
		(void) getdns_dict_get_int(rr_dict,
				"/rdata/type_covered", &rrtype);

	    if (rrtype == GETDNS_RRTYPE_DS || rrtype == GETDNS_RRTYPE_DNSKEY) {
		i = 0;
		append_to = support_rrs;
		fprintf(stderr, "-----------------------------------------\n");
	    }
	}
	fprintf(stdout, ">> Debug: RR: %s %d\n", fqdn, rrtype);
	rc = getdns_list_set_dict(append_to, i++, rr_dict);
	getdns_dict_destroy(rr_dict);
	if (rc)
	    break;
	n_rrs++;
    }
    fprintf(stdout, "Number of RRs in chain: %zu\n", n_rrs);

    if (!(trust_anchors = getdns_root_trust_anchor(NULL)))
	fprintf(stderr, "Could not read trust anchor\n");
    else {
	dnssec_status = getdns_validate_dnssec(
		to_validate_rrs, support_rrs, trust_anchors);
	fprintf(stdout, "dnssec status: %s\n",
			getdns_get_errorstr_by_id(dnssec_status));
    }
    getdns_list_destroy(support_rrs);
    getdns_list_destroy(trust_anchors);
    if (dnssec_status != GETDNS_DNSSEC_SECURE) {
    	getdns_list_destroy(to_validate_rrs);
	return 0;
    }
    if ((rc = getdns_list_get_length(to_validate_rrs, &n_rrs))) {
    	getdns_list_destroy(to_validate_rrs);
    	return 0;
    }

    if ((ssl_rc = SSL_dane_enable(ssl, hostname)) <= 0) {
	fprintf(stderr, "SSL_dane_enable() failed.\n");
	ERR_print_errors_fp(stderr);
    }
    for (i = 0; i < n_rrs; i++) {
	if ((rc = getdns_list_get_dict(to_validate_rrs, i, &rr_dict)) ||
	    (rc = getdns_dict_get_int(rr_dict, "type", &rrtype))) {
	    getdns_list_destroy(to_validate_rrs);
	    return 0;
	}
        if (rrtype != GETDNS_RRTYPE_TLSA)
	    continue;
	if ((rc = getdns_dict_get_int(rr_dict,
			"/rdata/certificate_usage", &usage)) ||
	    (rc = getdns_dict_get_int(rr_dict,
			"/rdata/matching_type", &mtype)) ||
	    (rc = getdns_dict_get_int(rr_dict,
			"/rdata/selector", &selector)) ||
	    (rc = getdns_dict_get_bindata(rr_dict,
			"/rdata/certificate_association_data",
			&cert_assoc_data))) {
	    getdns_list_destroy(to_validate_rrs);
	    return 0;
	}
	if ((ssl_rc = SSL_dane_tlsa_add(ssl, usage, selector, mtype,
			cert_assoc_data->data, cert_assoc_data->size)) <= 0) {

	    fprintf(stderr, "SSL_dane_tlsa_add() failed.\n");
	    ERR_print_errors_fp(stderr);
	}
    }
    return 1;
}


/*
 * main(): DANE TLSA test program.
 */

int main(int argc, char **argv)
{

    const char *progname, *port;
    char *hostname;
    struct addrinfo gai_hints;
    struct addrinfo *gai_result = NULL, *gaip;
    char ipstring[INET6_ADDRSTRLEN], *cp;
    struct sockaddr_in *sa4;
    struct sockaddr_in6 *sa6;
    int return_status = 1;                    /* program return status */
    int rc, sock, optcount;
    long rcl;

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    const SSL_CIPHER *cipher = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    BIO *sbio;

    uint8_t usage, selector, mtype;

    if ((progname = strrchr(argv[0], '/')))
        progname++;
    else
        progname = argv[0];

    optcount = parse_options(progname, argc, argv);
    argc -= optcount;
    argv += optcount;

    if (argc != 2) print_usage(progname);

    hostname = argv[0];
    port = argv[1];

    /*
     * Obtain address records with getaddrinfo()
     */

    memset(&gai_hints, 0, sizeof(struct addrinfo));
    gai_hints.ai_family = AF_UNSPEC;
    gai_hints.ai_socktype = SOCK_STREAM;
    gai_hints.ai_flags = 0;
    gai_hints.ai_protocol = 0;

    if ( (rc = getaddrinfo(hostname, port, &gai_hints, &gai_result)) != 0) {
        fprintf(stderr, "getaddrinfo: %s: %s\n", hostname, gai_strerror(rc));
        return 1;
    }

    /*
     * Initialize OpenSSL TLS library context, certificate authority
     * stores, and hostname verification parameters.
     */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);

    ctx = SSL_CTX_new(TLS_client_method());
    (void) SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);

    if (!CAfile) {
	if (!SSL_CTX_set_default_verify_paths(ctx)) {
	    fprintf(stderr, "Failed to load default certificate authorities.\n");
	    ERR_print_errors_fp(stderr);
	    goto cleanup;
	}
    } else {
	if (!SSL_CTX_load_verify_locations(ctx, CAfile, NULL)) {
	    fprintf(stderr, "Failed to load certificate authority store: %s.\n",
		    CAfile);
	    ERR_print_errors_fp(stderr);
	    goto cleanup;
	}
    }

    vpm = X509_VERIFY_PARAM_new();
    if (X509_VERIFY_PARAM_set1_host(vpm, hostname, 0) != 1) {
	fprintf(stderr, "Unable to set verify hostname parameter.\n");
	goto cleanup;
    }
    if (SSL_CTX_set1_param(ctx, vpm) != 1) {
	fprintf(stderr, "Unable to set context verify parameters.\n");
	goto cleanup;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify_depth(ctx, 10);

    /*
     * Set TLS extension for DNSSEC authentication chain. This sends
     * an empty extension of type 53 in the ClientHello message, and
     * registers a callback function to process the corresponding
     * extension from the server.
     */

    if (dnssec_chain && 
	!SSL_CTX_add_client_custom_ext(ctx, DNSSEC_CHAIN_EXT_TYPE, 
				       NULL, NULL, NULL,
				       dnssec_chain_parse_cb, hostname)) {
	fprintf(stderr,
		"Warning: Couldn't set DNSSEC chain extension, skipping\n");
    }

    /*
     * Enable DANE on the context.
     */

    if (SSL_CTX_dane_enable(ctx) <= 0) {
	fprintf(stderr, "Unable to enable DANE on SSL context.\n");
	goto cleanup;
    }

    /*
     * Loop over all addresses from getaddrinfo(), connect to each,
     * establish TLS connection, and perform DANE peer verification.
     */

    for (gaip = gai_result; gaip != NULL; gaip = gaip->ai_next) {

        if (gaip->ai_family == AF_INET) {
            sa4 = (struct sockaddr_in *) gaip->ai_addr;
            inet_ntop(AF_INET, &sa4->sin_addr, ipstring, INET6_ADDRSTRLEN);
            fprintf(stdout, "Connecting to IPv4 address: %s port %d\n",
                    ipstring, ntohs(sa4->sin_port));
        } else if (gaip->ai_family == AF_INET6) {
            sa6 = (struct sockaddr_in6 *) gaip->ai_addr;
            inet_ntop(AF_INET6, &sa6->sin6_addr, ipstring, INET6_ADDRSTRLEN);
            fprintf(stdout, "Connecting to IPv6 address: %s port %d\n",
                    ipstring, ntohs(sa6->sin6_port));
        }

        sock = socket(gaip->ai_family, gaip->ai_socktype, 0);
        if (sock == -1) {
            perror("socket");
            continue;
        }

        if (connect(sock, gaip->ai_addr, gaip->ai_addrlen) == -1) {
            perror("connect");
            close(sock);
            continue;
        }

	ssl = SSL_new(ctx);
	if (! ssl) {
	    fprintf(stderr, "SSL_new() failed.\n");
	    ERR_print_errors_fp(stderr);
	    close(sock);
	    continue;
	}

#if 0
	if (SSL_dane_enable(ssl, hostname) <= 0) {
	    fprintf(stderr, "SSL_dane_enable() failed.\n");
	    ERR_print_errors_fp(stderr);
	    SSL_free(ssl);
	    close(sock);
	    continue;
	}
#endif

	/* No partial label wildcards */
	SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

	/* Set TLS Server Name Indication extension */
	(void) SSL_set_tlsext_host_name(ssl, 
					(service_name? service_name : hostname));

	/* Set connect mode (client) and tie socket to TLS context */
	SSL_set_connect_state(ssl);
        sbio = BIO_new_socket(sock, BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);
	(void) SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	/* Do application specific STARTTLS conversation if requested */
	if (starttls != STARTTLS_NONE && !do_starttls(starttls, sbio, service_name, hostname)) {
	    fprintf(stderr, "STARTTLS failed.\n");
	    /* shutdown sbio here cleanly */
	    SSL_free(ssl);
	    close(sock);
	    continue;
	}

	/* Perform TLS connection handshake & peer authentication */
	if (SSL_connect(ssl) <= 0) {
	    fprintf(stderr, "TLS connection failed.\n");
	    ERR_print_errors_fp(stderr);
	    SSL_free(ssl);
	    close(sock);
	    continue;
	}

	fprintf(stdout, "%s handshake succeeded.\n", SSL_get_version(ssl));
	cipher = SSL_get_current_cipher(ssl);
	fprintf(stdout, "Cipher: %s %s\n",
		SSL_CIPHER_get_version(cipher), SSL_CIPHER_get_name(cipher));

	/* Print Certificate Chain information (if in debug mode) */
	if (debug)
	    print_peer_cert_chain(ssl);

	/* Report results of DANE or PKIX authentication of peer cert */
	if ((rcl = SSL_get_verify_result(ssl)) == X509_V_OK) {
	    return_status = 0;
	    const unsigned char *certdata;
	    size_t certdata_len;
	    const char *peername = SSL_get0_peername(ssl);
	    EVP_PKEY *mspki = NULL;
	    int depth = SSL_get0_dane_authority(ssl, NULL, &mspki);
	    if (depth >= 0) {
		(void) SSL_get0_dane_tlsa(ssl, &usage, &selector, &mtype, 
					  &certdata, &certdata_len);
		printf("DANE TLSA %d %d %d [%s...] %s at depth %d\n", 
		       usage, selector, mtype,
		       (cp = bin2hexstring( (uint8_t *) certdata, 6)),
		       (mspki != NULL) ? "TA public key verified certificate" :
		       depth ? "matched TA certificate" : "matched EE certificate",
		       depth);
		free(cp);
	    }
	    if (peername != NULL) {
		/* Name checks were in scope and matched the peername */
		fprintf(stdout, "Verified peername: %s\n", peername);
	    }
	    /* Print verified certificate chain (if in debug mode) */
	    if (debug)
		print_validated_chain(ssl);
	} else {
	    /* Authentication failed */
	    fprintf(stderr, "Error: peer authentication failed. rc=%ld (%s)\n",
                    rcl, X509_verify_cert_error_string(rcl));
	    ERR_print_errors_fp(stderr);
	}

#if 1
	int readn;
	char buffer[MYBUFSIZE];

	/* This doesn't work yet */
	/* Do minimal HTTP 1.0 conversation*/

	snprintf( buffer, sizeof(buffer)
	        , "GET / HTTP/1.0\r\nHost: %s\r\n\r\n"
	        , hostname
		);
	SSL_write(ssl, buffer, strlen(buffer));
	while (1) {
	    if (debug)
	    	fprintf(stdout, "about to read() ..\n");
	    readn = SSL_read(ssl, buffer, MYBUFSIZE);
	    if (debug)
	    	fprintf(stdout, "read %d octets ..\n", readn);
	    if (readn == 0)
		break;
	    buffer[readn] = '\0';
	    fprintf(stdout, "%s", buffer);
	}
#endif
	/* Shutdown */
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sock);
	(void) fputc('\n', stdout);

    }

cleanup:
    freeaddrinfo(gai_result);
    if (ctx) {
	X509_VERIFY_PARAM_free(vpm);
	SSL_CTX_free(ctx);
    }

    return return_status;
}
