/*
 * chainserver.c
 * Work-in-Progress ...
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
#include <sys/wait.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>
#include <getdns/getdns_ext_libevent.h>

#include "utils.h"


/*
 * DNSSEC Authentication Chain TLS extension type value
 */

#define DNSSEC_CHAIN_EXT_TYPE 53


/*
 * Server certificate and key files (PEM format) - hardcoded defaults.
 */

#define SERVER_CERT "server.crt"
#define SERVER_KEY  "server.key"


/*
 * Enumerated Types and Global variables
 */

enum AUTH_MODE { 
    MODE_BOTH=0, 
    MODE_DANE, 
    MODE_PKIX 
};

int debug = 0;
uint16_t port;
char *port_str;
enum AUTH_MODE auth_mode = MODE_BOTH;
char *service_name = NULL;

char *server_name = NULL;
char *certfile = SERVER_CERT;
char *keyfile = SERVER_KEY;
char *CAfile = NULL;
int clientauth = 0;
int dnssec_chain = 1;
unsigned char *dnssec_chain_data = NULL;
char *proxy = NULL;

#define UNUSED_PARAM(x) ((void) (x))


/*
 * usage(): Print usage string and exit.
 */

void print_usage(const char *progname)
{
    fprintf(stdout, "\nUsage: %s [options] <portnumber>\n\n"
            "       -h:               print this help message\n"
            "       -d:               debug mode\n"
	    "       -sname <name>:    server name\n"
	    "       -cert <file>:     server certificate file\n"
	    "       -key <file>:      server private key file\n"
	    "       -clientauth:      require client authentication\n"
	    "       -CAfile <file>:   CA file for client authentication\n"
	    "       -proxy <ip>:<port>: IPv4 address and port to forward to\n"
	    "\n",
	    progname);
    exit(1);
}


/*
 * parse_options()
 */

void parse_options(const char *progname, int argc, char **argv)
{
    int i;
    char *optword;

    for (i = 1; i < argc; i++) {

	optword = argv[i];

	if (!strcmp(optword, "-h")) {
	    print_usage(progname);
	} else if (!strcmp(optword, "-d")) {
	    debug = 1;
	} else if (!strcmp(optword, "-sname")) {
	    if (++i >= argc || !*argv[i]) {
		fprintf(stderr, "-sname: server name.\n");
		print_usage(progname);
	    }
	    server_name = argv[i];
	} else if (!strcmp(optword, "-cert")) {
	    if (++i >= argc || !*argv[i]) {
		fprintf(stderr, "-cert: certificate file expected.\n");
		print_usage(progname);
	    }
	    certfile = argv[i];
	} else if (!strcmp(optword, "-key")) {
	    if (++i >= argc || !*argv[i]) {
		fprintf(stderr, "-key: private key file expected.\n");
		print_usage(progname);
	    }
	    keyfile = argv[i];
	} else if (!strcmp(optword, "-CAfile")) {
	    if (++i >= argc || !*argv[i]) {
		fprintf(stderr, "-CAfile: CA file expected.\n");
		print_usage(progname);
	    }
	    CAfile = argv[i];
	} else if (!strcmp(optword, "-clientauth")) {
	    clientauth = 1;
	} else if (!strcmp(optword, "-proxy")) {
	    if (++i >= argc || !*argv[i]) {
		fprintf(stderr, "-proxy: proxy address and port expected.\n");
		print_usage(progname);
	    }
	    proxy = argv[i];
	} else if (optword[0] == '-') {
	    fprintf(stderr, "Unrecognized option: %s\n", optword);
	    print_usage(progname);
	} else {
	    break;
	}

    }

    if (optword == NULL) {
	fprintf(stderr, "Error: no port number specified.\n");
	print_usage(progname);
    } else if ((argc - i) != 1) {
	fprintf(stderr, "Error: too many arguments.\n");
	print_usage(progname);
    }

    port_str = optword;
    port = atoi(optword);

    if (!server_name) {
	server_name = malloc(512);
	gethostname(server_name, 512);
    }

    return;
}


/*
 * Linked List of Wire format RRs and associated routines.
 */


typedef struct wirerr {
    getdns_bindata *node;
    struct wirerr *next;
} wirerr;

wirerr *wirerr_list = NULL;
size_t wirerr_count = 0;
size_t wirerr_size = 0;

wirerr *insert_wirerr(wirerr *current, getdns_bindata *new)
{
    wirerr *w = malloc(sizeof(wirerr));
    w->node = new;
    w->next = NULL;
    wirerr_count++;
    wirerr_size += new->size;

    if (current == NULL) {
        wirerr_list = w;
    } else
        current->next = w;
    return w;
}

void free_wirerr_list(wirerr *head)
{
    wirerr *current;
    while ((current = head) != NULL) {
        head = head->next;
        free(current->node->data);
	free(current->node);
        free(current);
    }
    return;
}


/*
 * child signal handler
 */

void sig_chld(int signo)
{
    pid_t pid;
    int stat;

    UNUSED_PARAM(signo);
    while ( (pid = waitpid(-1, &stat, WNOHANG)) > 0) {
    }
    return;
}


/*
 * getchain(): get DNSSEC chain data for given qname, qtype
 */

getdns_bindata *getchain(char *qname, uint16_t qtype)
{
    unsigned char *cp;
    uint32_t status;
    getdns_context *ctx = NULL;
    getdns_return_t rc;
    getdns_dict    *extensions = NULL;
    getdns_dict *response;
    getdns_bindata *chaindata = malloc(sizeof(getdns_bindata));
    wirerr *wp = wirerr_list;

    rc = getdns_context_create(&ctx, 1);
    if (rc != GETDNS_RETURN_GOOD) {
	(void) fprintf(stderr, "Context creation failed: %d", rc);
	return NULL;
    }

    if (! (extensions = getdns_dict_create())) {
	fprintf(stderr, "FAIL: Error creating extensions dict\n");
	return NULL;
    }

    if ((rc = getdns_dict_set_int(extensions, "dnssec_return_only_secure",
				  GETDNS_EXTENSION_TRUE))) {
	fprintf(stderr, "FAIL: setting dnssec_return_only_secure: %s\n",
		getdns_get_errorstr_by_id(rc));
	return NULL;
    }

    if ((rc = getdns_dict_set_int(extensions, "dnssec_return_validation_chain",
				  GETDNS_EXTENSION_TRUE))) {
	fprintf(stderr, "FAIL: setting +dnssec_return_validation_chain: %s\n",
		getdns_get_errorstr_by_id(rc));
	return NULL;
    }

    rc = getdns_general_sync(ctx, qname, qtype, extensions, &response);
    if (rc != GETDNS_RETURN_GOOD) {
	(void) fprintf(stderr, "getdns_general() failed, rc=%d, %s\n", 
		       rc, getdns_get_errorstr_by_id(rc));
	getdns_context_destroy(ctx);
	return NULL;
    }

    (void) getdns_dict_get_int(response, "status", &status);

    switch (status) {
    case GETDNS_RESPSTATUS_GOOD:
	break;
    case GETDNS_RESPSTATUS_NO_NAME:
	fprintf(stderr, "FAIL: %s: Non existent domain name.\n", qname);
	return NULL;
    case GETDNS_RESPSTATUS_ALL_TIMEOUT:
	fprintf(stderr, "FAIL: %s: Query timed out.\n", qname);
	return NULL;
    case GETDNS_RESPSTATUS_NO_SECURE_ANSWERS:
	fprintf(stderr, "%s: Insecure address records.\n", qname);
	return NULL;
    case GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS:
	fprintf(stderr, "FAIL: %s: All bogus answers.\n", qname);
	return NULL;
    default:
        fprintf(stderr, "FAIL: %s: error status code: %d.\n", qname, status);
        return NULL;
    }

    getdns_list *replies_tree;
    rc = getdns_dict_get_list(response, "replies_tree", &replies_tree);
    if (rc != GETDNS_RETURN_GOOD) {
	(void) fprintf(stdout, "dict_get_list: replies_tree: rc=%d\n", rc);
	return NULL;
    }

    size_t reply_count;
    (void) getdns_list_get_length(replies_tree, &reply_count);

    size_t i;
    for ( i = 0; i < reply_count; i++ ) {

	getdns_dict *reply;
	getdns_list *answer;
	size_t rr_count;
	size_t j;

	(void) getdns_list_get_dict(replies_tree, i, &reply);
	(void) getdns_dict_get_list(reply, "answer", &answer);
	(void) getdns_list_get_length(answer, &rr_count);

	if (rr_count == 0) {
	    (void) fprintf(stderr, "FAIL: %s: NODATA response.\n", qname);
	    return NULL;
	}

	for ( j = 0; j < rr_count; j++ ) {
	    getdns_dict *rr = NULL;
	    getdns_bindata *wire = malloc(sizeof(getdns_bindata));
	    (void) getdns_list_get_dict(answer, j, &rr);
	    rc = getdns_rr_dict2wire(rr, &wire->data, &wire->size);
            if (rc != GETDNS_RETURN_GOOD) {
		(void) fprintf(stderr, "rrdict2wire() failed: %d\n", rc);
                return NULL;
            }
	    wp = insert_wirerr(wp, wire);
	}

    }

    getdns_list *val_chain;
    rc = getdns_dict_get_list(response, "validation_chain", &val_chain);
    if (rc != GETDNS_RETURN_GOOD) {
        (void) fprintf(stderr, "FAIL: getting validation_chain: rc=%d\n", rc);
	return NULL;
    }

    size_t rr_count;
    (void) getdns_list_get_length(val_chain, &rr_count);

    for ( i = 0; i < rr_count; i++ ) {	
	getdns_dict *rr = NULL;
        getdns_bindata *wire = malloc(sizeof(getdns_bindata));
	(void) getdns_list_get_dict(val_chain, i, &rr);
	rc = getdns_rr_dict2wire(rr, &wire->data, &wire->size);
        if (rc != GETDNS_RETURN_GOOD) {
            (void) fprintf(stderr, "rrdict2wire() failed: %d\n", rc);
            return NULL;
        }
	wp = insert_wirerr(wp, wire);
    }

    getdns_context_destroy(ctx);

    /* 
     * Generate dnssec_chain extension data and return pointer to it.
     */
    chaindata->size = 4 + wirerr_size;
    chaindata->data = malloc(chaindata->size);

    cp = chaindata->data;
    *(cp + 0) = (DNSSEC_CHAIN_EXT_TYPE >> 8) & 0xff;  /* Extension Type 53 */
    *(cp + 1) = (DNSSEC_CHAIN_EXT_TYPE) & 0xff;
    *(cp + 2) = (wirerr_size >> 8) & 0xff;            /* Extension (data) Size */
    *(cp + 3) = (wirerr_size) & 0xff;

    cp = chaindata->data + 4;

    for (wp = wirerr_list; wp != NULL; wp = wp->next) {
	getdns_bindata *g = wp->node;
	(void) memcpy(cp, g->data, g->size);
	cp += g->size;
    }

#if 0
    fprintf(stdout, "\nDEBUG (REMOVE ME) chaindata:\n%s\n\n", 
	    bindata2hexstring(chaindata));
#endif

    return chaindata;
}


#define MYBUFSIZE 2048

/*
 * do_http()
 */

int do_http(BIO *sbio)
{

    char buffer[MYBUFSIZE];
    int readn;
    int seen_get_request = 0;

    /* read request */
    if ((readn = BIO_read(sbio, buffer, MYBUFSIZE)) <= 0)
	return 0;

    buffer[readn] = '\0';
    if (debug) {
	fprintf(stdout, "recv: (%d) %s\n", readn, buffer);
    }
    if (strncmp("GET ", buffer, 4) == 0) {
	seen_get_request = 1;
    }
    if (!seen_get_request) {
	fprintf(stdout, "Did not see HTTP request from client.\n");
	return 0;
    }

    /* send response */
    BIO_puts(sbio, "HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n");
    BIO_puts(sbio, "<html><title>Chainserver</title>\n<BODY BGCOLOR=\"#ffffff\">\n");
    BIO_puts(sbio, "<h2>Chainserver</h2>\n");
    BIO_puts(sbio, "<pre>\n");
    BIO_puts(sbio, OpenSSL_version(OPENSSL_VERSION));
    BIO_puts(sbio, "\n");
    BIO_puts(sbio, "</pre>\n</body>\n</html>\n");
    (void) BIO_flush(sbio);

    return 1;
}

struct chunk {
	struct chunk *next;
	size_t        size;
	uint8_t       data[];
};

struct session {
	BIO *sbio;
	int remote;
	struct chunk *to_bio;
	struct chunk *to_remote;
};
static void free_chunks(struct chunk *c)
{
	if (c) {
		free_chunks(c->next);
		free(c);
	}
}

static void do_bio_read(struct session *s)
{
	uint8_t buf[65536];
	ssize_t len = BIO_read(s->sbio, buf, sizeof(buf));
	struct chunk **chunk_p;

	if (len == 0) {
		/* close */
		free_chunks(s->to_remote);
		free_chunks(s->to_bio);
		s->to_remote = s->to_bio = NULL;
		BIO_free_all(s->sbio);
		s->sbio = NULL;
		close(s->remote);
		s->remote = -1;
		return;
	}
	if (len < 0) /* error */
		return;

	/* Append a new chunk */
	for (chunk_p = &s->to_remote; *chunk_p; chunk_p = &(*chunk_p)->next)
		; /* pass */

	*chunk_p = (struct chunk *)malloc(sizeof(struct chunk) + len);
	(*chunk_p)->next = NULL;
	(*chunk_p)->size = len;
	memcpy((*chunk_p)->data, buf, len);
}

static void do_bio_write(struct session *s)
{
	struct chunk *c = s->to_bio;
	if (!c)
		return;

	s->to_bio = c->next;
	BIO_write(s->sbio, c->data, c->size);
	free(c);
}

static void do_remote_read(struct session *s)
{
	uint8_t buf[65536];
	ssize_t len = read(s->remote, buf, sizeof(buf));
	struct chunk **chunk_p;
	SSL *ssl;
	int sock;

	if (len == 0) {
		/* close */
		free_chunks(s->to_remote);
		free_chunks(s->to_bio);
		s->to_remote = s->to_bio = NULL;
		BIO_get_ssl(s->sbio, &ssl);
		SSL_shutdown(ssl);
		BIO_get_fd(s->sbio, &sock);
		close(sock);
		BIO_free_all(s->sbio);
		s->sbio = NULL;
		s->remote = -1;
		return;
	}
	if (len < 0) /* error */ {
		perror("read()");
		return;
	}

	/* Append a new chunk */
	for (chunk_p = &s->to_bio; *chunk_p; chunk_p = &(*chunk_p)->next)
		; /* pass */

	*chunk_p = (struct chunk *)malloc(sizeof(struct chunk) + len);
	(*chunk_p)->next = NULL;
	(*chunk_p)->size = len;
	memcpy((*chunk_p)->data, buf, len);
}

static void do_remote_write(struct session *s)
{
	struct chunk *c = s->to_remote;
	if (!c)
		return;

	s->to_remote = c->next;
	write(s->remote, c->data, c->size);
	free(c);
}

static void do_proxy(BIO *acpt)
{
	int accept_sock;
	fd_set rfds, wfds;
	struct session sessions[FD_SETSIZE];
	int i, max_fd, r, sock;
	BIO *sbio;
	struct sockaddr_in sa_in;
	socklen_t sa_len = sizeof(sa_in);


	if (!strchr(proxy, ':')) {
		fprintf(stderr, "Could not read port from proxy address\n");
		exit(EXIT_FAILURE);
	}
	sa_in.sin_family = AF_INET;
	sa_in.sin_port = htons(atoi(strchr(proxy, ':')+1));
	*strchr(proxy, ':') = 0;
	if (inet_pton(AF_INET, proxy, (void *)&sa_in.sin_addr.s_addr) <= 0) {
		perror("inet_pton()");
		exit(EXIT_FAILURE);
	}

	memset(&sessions, 0, sizeof(sessions));
	BIO_get_fd(acpt, &accept_sock);
	for (;;) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_SET(accept_sock, &rfds);

		max_fd = accept_sock;
		for (i = 0; i < FD_SETSIZE; i++) {
			if (!sessions[i].sbio)
				continue;
			FD_SET(i, &rfds);
			if (sessions[i].to_bio)
				FD_SET(i, &wfds);
			FD_SET(sessions[i].remote, &rfds);
			if (sessions[i].to_remote)
				FD_SET(sessions[i].remote, &wfds);
			if (i > max_fd)
				max_fd = i;
			if (sessions[i].remote > max_fd)
				max_fd = sessions[i].remote;
		}
		max_fd += 1;
		r = select(max_fd, &rfds, &wfds, NULL, NULL);
		if (r == -1)
			perror("select()");

		while (FD_ISSET(accept_sock, &rfds)) {
			if(BIO_do_accept(acpt) <= 0) {
			       fprintf(stderr, "Error in connection\n");
			       ERR_print_errors_fp(stderr);
			       break;
			}

			sbio = BIO_pop(acpt);

			if(BIO_do_handshake(sbio) <= 0) {
			       fprintf(stderr, "Error in SSL handshake\n");
			       ERR_print_errors_fp(stderr);
			       break;
			}

			BIO_get_fd(sbio, &sock);
			sessions[sock].sbio = sbio;
			sessions[sock].remote = socket(AF_INET, SOCK_STREAM, 0);
			if (connect(sessions[sock].remote,
			    (struct sockaddr*)&sa_in, sa_len) < 0) {
				perror("connect()");
			}
			break;
		}
		for (i = 0; i < FD_SETSIZE; i++) {
			if (!sessions[i].sbio)
				continue;

			if (FD_ISSET(i, &wfds)) {
				do_bio_write(&sessions[i]);
			}
			if (FD_ISSET(sessions[i].remote, &wfds)) {
				do_remote_write(&sessions[i]);
			}
			if (FD_ISSET(i, &rfds)) {
				do_bio_read(&sessions[i]);
			}
			if (FD_ISSET(sessions[i].remote, &rfds)) {
				do_remote_read(&sessions[i]);
			}
		}
	}
}

/*
 * main(): DANE chainserver program
 */

int main(int argc, char **argv)
{

    const char *progname;
    char tlsa_name[512];
    getdns_bindata *chaindata = NULL;
    int return_status = 1;                    /* program return status */
    int sock;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    const SSL_CIPHER *cipher = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    BIO *sbio, *acpt;

    /* uint8_t usage, selector, mtype; */

    if ((progname = strrchr(argv[0], '/')))
        progname++;
    else
        progname = argv[0];

    parse_options(progname, argc, argv);

    /*
     * Query my TLSA record and build DNSSEC chain data for it.
     */

    snprintf(tlsa_name, 512, "_%d._tcp.%s", port, server_name);
    chaindata = getchain(tlsa_name, GETDNS_RRTYPE_TLSA);
    if (chaindata) {
	fprintf(stdout, "Got DNSSEC chain data for %s, size=%zu octets\n", 
		tlsa_name, chaindata->size - 4);
    } else {
	fprintf(stdout, "Failed to get DNSSEC chain data for %s\n", tlsa_name);
	/* return 1; */
    }

    /*
     * Initialize OpenSSL TLS library context, certificate authority
     * stores, and hostname verification parameters.
     */

    SSL_load_error_strings();
    SSL_library_init();

    ctx = SSL_CTX_new(TLS_server_method());
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

    /* 
     * Read my server certificate and private key
     */

    if (!SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM)) {
	fprintf(stderr, "Failed to load server certificate.\n");
	ERR_print_errors_fp(stderr);
	goto cleanup;
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM)) {
	fprintf(stderr, "Failed to load server private key.\n");
	ERR_print_errors_fp(stderr);
	goto cleanup;
    }   

    /*
     * load dnssec_chain Server Hello extensions into context
     */

    if (chaindata)
	if (!SSL_CTX_use_serverinfo(ctx, chaindata->data, chaindata->size)) {
	    fprintf(stderr, "failed loading dnssec_chain_data extension.\n");
	    goto cleanup;
	}

    /*
     * Setup session resumption capability
     */

    const unsigned char *sid_ctx = (const unsigned char *) "chainserver";
    (void) SSL_CTX_set_session_id_context(ctx, sid_ctx, sizeof(sid_ctx));

    
    /* New SSL BIO setup as server */
    sbio = BIO_new_ssl(ctx,0);

    BIO_get_ssl(sbio, &ssl);
    if(!ssl) {
        fprintf(stderr, "Can't locate SSL pointer\n");
        /* whatever ... */
    }

    /* Don't want any retries */
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    acpt = BIO_new_accept(port_str);

    /* By doing this when a new connection is established
     * we automatically have sbio inserted into it. The
     * BIO chain is now 'swallowed' by the accept BIO and
     * will be freed when the accept BIO is freed.
     */

    BIO_set_accept_bios(acpt,sbio);

    /* Setup accept BIO */
    if(BIO_do_accept(acpt) <= 0) {
	   fprintf(stderr, "Error setting up accept BIO\n");
	   ERR_print_errors_fp(stderr);
	   return 0;
    }

    if (proxy)
	    do_proxy(acpt);

    else for (;;) {
	/* Now wait for incoming connection */
	if(BIO_do_accept(acpt) <= 0) {
	       fprintf(stderr, "Error in connection\n");
	       ERR_print_errors_fp(stderr);
	       return 0;
	}

	sbio = BIO_pop(acpt);

	if(BIO_do_handshake(sbio) <= 0) {
	       fprintf(stderr, "Error in SSL handshake\n");
	       ERR_print_errors_fp(stderr);
	       return 0;
	}
	BIO_get_ssl(sbio, ssl);

	cipher = SSL_get_current_cipher(ssl);
	fprintf(stdout, "%s Cipher: %s %s\n\n", SSL_get_version(ssl),
		SSL_CIPHER_get_version(cipher), SSL_CIPHER_get_name(cipher));

	do_http(sbio);
	SSL_shutdown(ssl);
	BIO_get_fd(sbio, &sock);
	close(sock);
    	BIO_free_all(sbio);
    }

cleanup:
    free(dnssec_chain_data);
    if (ctx) {
	X509_VERIFY_PARAM_free(vpm);
	SSL_CTX_free(ctx);
    }
    return return_status;
}
