#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <pthread.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "mongoc-b64.h"

#define CERT_GOOD_SERVER "server.pem"
#define CERT_CA "ca.pem"
#define INTERMEDIATE_CA "intermediate_ca.pem"

#define BASIC_CONSTRAINTS_CA_TRUE 1 << 0
#define BASIC_CONSTRAINTS_CA_FALSE 1 << 1

#define KEY_USAGE_DIGITALSIGNATURE 1 << 0
#define KEY_USAGE_NONREPUDIATION 1 << 1
#define KEY_USAGE_KEYENCIPHERMENT 1 << 2
#define KEY_USAGE_DATAENCIPHERMENT 1 << 3
#define KEY_USAGE_KEYAGREEMENT 1 << 4
#define KEY_USAGE_KEYCERTSIGN 1 << 5
#define KEY_USAGE_CRLSIGN 1 << 6
#define KEY_USAGE_ENCIPHERONLY 1 << 7
#define KEY_USAGE_DECIPHERONLY 1 << 8

#define EXT_KEY_USAGE_SERVERAUTH 1 << 0
#define EXT_KEY_USAGE_CLIENTAUTH 1 << 1
#define EXT_KEY_USAGE_CODESIGNING 1 << 2
#define EXT_KEY_USAGE_EMAILPROTECTION 1 << 3
#define EXT_KEY_USAGE_TIMESTAMPING 1 << 4
#define EXT_KEY_USAGE_MSCODEIND 1 << 5
#define EXT_KEY_USAGE_MSCODECOM 1 << 6
#define EXT_KEY_USAGE_MSCTLSIGN 1 << 7
#define EXT_KEY_USAGE_MSSGC 1 << 8
#define EXT_KEY_USAGE_MSEFS 1 << 9
#define EXT_KEY_USAGE_NSSGC 1 << 10

#define MAX_B64_SIZE 1024
#define MAX_CONFIG_SIZE MAX_B64_SIZE

#define TOP_LEVEL_DOMAIN ".vcap.me"

#ifndef __CONST_SOCKADDR_ARG
typedef const struct sockaddr *__CONST_SOCKADDR_ARG;
#endif

/* bind/connect declaration used as callback */
typedef int (*cb) (int fd, __CONST_SOCKADDR_ARG, socklen_t addrlen);

/* Arguments to our thread */
typedef struct _worker_config {
   int fd_client;
   int server_port;
} worker_config;

// Holds all the TLS options configurable through the hostname.
typedef struct _tls_options {
   // TLS Options
   char *ciphers;       // Acceptable TLS cipher suites
   int tls_versions;    // Acceptable TLS_VERSION_* versions
   int tls_compression; // Enable TLS compression

   // Use hard coded server PEM file
   char *keyfile;
   char *issuerfile;

   // Certificate Generation Options
   char *cn;           // CN: Common Name
   char *issuer;       // Signing CA: root, intermediate, unknown
   int64_t not_before; // Not valid before datetime
   int64_t not_after;  // Not valid after datetime
   char *san; // SAN: Subject Alt Names, list of IP Addresses or DNS names, eg
              // "IP:127.0.0.1,DNS:server"

   // Basic Constraints
   int basic_constraints;

   // Key Usage
   int key_usage;
   // Extended Key Usage
   int ext_key_usage;
} tls_options;

void
_free_tls_options (tls_options *options)
{
   if (options->ciphers) {
      free (options->ciphers);
   }
   if (options->keyfile) {
      free (options->keyfile);
   }
   if (options->cn) {
      free (options->cn);
   }
   if (options->issuer) {
      free (options->issuer);
   }
   if (options->san) {
      free (options->san);
   }
   free (options);
}

void
_init_openssl ()
{
   SSL_load_error_strings ();
   SSL_library_init ();
}

int
_mongoc_ssl_setup_ca (SSL_CTX *ssl_ctx,
                      const char *ca_file,
                      const char *ca_path)
{
   if ((ca_file || ca_path) &&
       !SSL_CTX_load_verify_locations (ssl_ctx, ca_file, ca_path)) {
      return 0;
   }
   if (!SSL_CTX_set_default_verify_paths (ssl_ctx)) {
      return 0;
   }

   return 1;
}

int
_mongoc_ssl_setup_pem_file (SSL_CTX *ssl_ctx, const char *pem_file)
{
   if (!SSL_CTX_use_certificate_chain_file (ssl_ctx, pem_file)) {
      return 0;
   }

   if (!SSL_CTX_use_PrivateKey_file (ssl_ctx, pem_file, SSL_FILETYPE_PEM)) {
      return 0;
   }

   if (!SSL_CTX_check_private_key (ssl_ctx)) {
      return 0;
   }

   return 1;
}

char *
_hostname_to_b64 (const char *servername)
{
   int i, j;
   int server_len = strlen (servername);

   if (strstr (servername, TOP_LEVEL_DOMAIN) == NULL) {
      // hostnames must end with well known TOP_LEVEL_DOMAIN
      return NULL;
   }
   server_len -= strlen (TOP_LEVEL_DOMAIN);

   // Possibly need 3 extra bytes for '=' padding.
   char *base64 = calloc (server_len + 4, 1);
   if (!base64) {
      return NULL;
   }

   // Remove '.' chunks added to create valid hostname labels and convert
   // '.' to '+' and '-' to '/'.
   for (i = 0, j = 0; i < server_len; i++) {
      if ((i + 1) % 64 == 0) {
         // Each 64th character must be a '.'
         if (servername[i] != '.') {
            free (base64);
            return NULL;
         }
         continue;
      }
      char c = servername[i];
      switch (c) {
      case '.':
         c = '+';
         break;
      case '-':
         c = '/';
         break;
      default:
         break;
      }
      base64[j++] = c;
   }

   // Add padding that was stripped because '=' is not a valid in a hostname.
   while (j % 4) {
      base64[j++] = '=';
   }
   return base64;
}

char *
_b64_to_hostname (const char *b64)
{
   int i, j;
   int b64_len = strlen (b64);

   char *hostname = calloc (b64_len + 100, 1);
   if (!hostname) {
      return NULL;
   }

   // Add '.' chunks added to create valid hostname labels and convert
   // '+' to '.' and '/' to '-'.
   for (i = 0, j = 0; j < b64_len && b64[j] != '='; i++) {
      if ((i + 1) % 64 == 0) {
         // Each 64th character must be a '.'
         hostname[i] = '.';
         continue;
      }
      char c = b64[j++];
      switch (c) {
      case '+':
         c = '.';
         break;
      case '/':
         c = '-';
         break;
      default:
         break;
      }
      hostname[i] = c;
   }
   for (j = 0; j < strlen (TOP_LEVEL_DOMAIN); j++) {
      hostname[i++] = TOP_LEVEL_DOMAIN[j];
   }
   return hostname;
}

char *
_config_to_hostname (const char *config)
{
   int config_len = strlen (config);
   char b64_hostname[MAX_B64_SIZE] = {0};

   int b64_len = mongoc_b64_ntop ((const uint8_t *) config,
                                  config_len,
                                  b64_hostname,
                                  sizeof (b64_hostname));
   if (-1 == b64_len) {
      return NULL;
   }
   return _b64_to_hostname (b64_hostname);
}

char *
_hostname_to_config (const char *hostname)
{
   char *b64_hostname = _hostname_to_b64 (hostname);
   if (!b64_hostname) {
      return NULL;
   }
   char *tls_config = calloc (MAX_CONFIG_SIZE, 1);
   int tls_config_len;

   tls_config_len = mongoc_b64_pton (
      (const char *) b64_hostname, (uint8_t *) tls_config, MAX_CONFIG_SIZE);
   free (b64_hostname);
   if (-1 == tls_config_len) {
      free (tls_config);
      return NULL;
   }
   return tls_config;
}

int
_mongoc_decode_hostname (const char *servername, tls_options *settings)
{
   if (!servername || !settings) {
      return 0;
   }
   char *tls_config = _hostname_to_config (servername);
   if (!tls_config) {
      return 0;
   }

   char *sep = "\n";
   char *line, *key, *value, *last;
   for (line = strtok_r (tls_config, sep, &last); line;
        line = strtok_r (NULL, sep, &last)) {
      key = line;
      value = strchr (line, '=');
      if (value) {
         *value = '\0';
         value++;
      }
      if (strcmp (key, "A") == 0) {
      } else if (strcmp (key, "B") == 0) {
      } else if (strcmp (key, "C") == 0) {
      } else {
         // Unknown key..
      }
   }
   free (tls_config);

   settings->ciphers = strdup ("HIGH:!EXPORT:!aNULL@STRENGTH");
   settings->cn = strdup (servername);
   settings->san = strdup ("DNS:some.server.pass.vcap.me,IP:192.168.0.1");
   settings->issuer =
      strdup ("root"); // Signing CA: root, intermediate, unknown
   settings->not_before = time (NULL);
   settings->not_after = time (NULL) + (7 * 24 * 60 * 60);

   settings->basic_constraints = BASIC_CONSTRAINTS_CA_FALSE;
   settings->key_usage = KEY_USAGE_DIGITALSIGNATURE;
   settings->ext_key_usage = EXT_KEY_USAGE_SERVERAUTH |
                             EXT_KEY_USAGE_CLIENTAUTH |
                             EXT_KEY_USAGE_CODESIGNING;

   return 1;
}


int
_mongoc_ssl_setup_certs (SSL_CTX *ssl_ctx, const char *ca, const char *private)
{
   if (!_mongoc_ssl_setup_ca (ssl_ctx, ca, NULL)) {
      return 0;
   }

   if (!_mongoc_ssl_setup_pem_file (ssl_ctx, private)) {
      return 0;
   }
   return 1;
}

void
fail (const char *msg)
{
   fprintf (stderr, "%s\n", msg);
   abort ();
}

int
_mongoc_generate_csr (const char *servername, const tls_options *settings)
{
   RSA *rsa;
   EVP_PKEY *pkey;
   X509_REQ *x509req;
   X509_NAME *name;
   BIO *out;
   int pathlen = strlen (servername) + strlen ("certs/.key.pem") + 1;
   char *path = malloc (pathlen);

   snprintf (path, pathlen, "certs/%s.key.pem", servername);

   pkey = EVP_PKEY_new ();
   if (!pkey) {
      fail ("couldn't generate key");
   }

   rsa = RSA_generate_key (2048, RSA_F4, NULL, NULL);
   if (!EVP_PKEY_assign_RSA (pkey, rsa)) {
      fail ("couldn't assign the key");
   }

   x509req = X509_REQ_new ();
   X509_REQ_set_pubkey (x509req, pkey);

   name = X509_NAME_new ();
   X509_NAME_add_entry_by_txt (
      name, "C", MBSTRING_ASC, (const unsigned char *) "IS", -1, -1, 0);
   X509_NAME_add_entry_by_txt (
      name, "O", MBSTRING_ASC, (const unsigned char *) "MongoDB", -1, -1, 0);
   X509_NAME_add_entry_by_txt (
      name,
      "OU",
      MBSTRING_ASC,
      (const unsigned char *) "SkunkWorks tls-server-generator",
      -1,
      -1,
      0);
   X509_NAME_add_entry_by_txt (name,
                               "CN",
                               MBSTRING_ASC,
                               (const unsigned char *) settings->cn,
                               -1,
                               -1,
                               0);

   X509_REQ_set_subject_name (x509req, name);
   X509_REQ_set_version (x509req, 2);

   if (!X509_REQ_sign (x509req, pkey, EVP_sha1 ())) {
      fail ("req_sign");
   }

   out = BIO_new_file (path, "wb");
   if (!PEM_write_bio_PrivateKey (out, pkey, NULL, NULL, 0, NULL, NULL)) {
      fail ("can't write private key");
   }

   BIO_free_all (out);
   path[pathlen - 8] = 'c';
   path[pathlen - 7] = 's';
   path[pathlen - 6] = 'r';

   out = BIO_new_file (path, "wb");
   if (!PEM_write_bio_X509_REQ_NEW (out, x509req)) {
      fail ("coudln't write csr");
   }
   BIO_free_all (out);

   EVP_PKEY_free (pkey);
   X509_REQ_free (x509req);
   free (path);

   return 1;
}

void
_mongoc_basic_constraints_to_str (int flags, char *str)
{
   int l = 0;

   if (flags & BASIC_CONSTRAINTS_CA_FALSE) {
      l += sprintf (str + l, "CA:FALSE");
   }
   if (flags & BASIC_CONSTRAINTS_CA_TRUE) {
      l += sprintf (str + l, "CA:TRUE");
   }
}
void
_mongoc_key_usage (int flags, char *str)
{
   int l = 0;

   if (flags & KEY_USAGE_DIGITALSIGNATURE) {
      l += sprintf (str + l, "digitalSignature");
   }
   if (flags & KEY_USAGE_NONREPUDIATION) {
      l += sprintf (str + l, "nonRepudiation");
   }
   if (flags & KEY_USAGE_KEYENCIPHERMENT) {
      l += sprintf (str + l, "keyEncipherment");
   }
   if (flags & KEY_USAGE_DATAENCIPHERMENT) {
      l += sprintf (str + l, "dataEncipherment");
   }
   if (flags & KEY_USAGE_KEYAGREEMENT) {
      l += sprintf (str + l, "keyAgreement");
   }
   if (flags & KEY_USAGE_KEYCERTSIGN) {
      l += sprintf (str + l, "keyCertSign");
   }
   if (flags & KEY_USAGE_CRLSIGN) {
      l += sprintf (str + l, "cRLSign");
   }
   if (flags & KEY_USAGE_ENCIPHERONLY) {
      l += sprintf (str + l, "encipherOnly");
   }
   if (flags & KEY_USAGE_DECIPHERONLY) {
      l += sprintf (str + l, "decipherOnly");
   }
}

void
_mongoc_ext_key_usage (int flags, char *str)
{
   int l = 0;

   if (flags & EXT_KEY_USAGE_SERVERAUTH) {
      l += sprintf (str + l, "serverAuth");
   }
   if (flags & EXT_KEY_USAGE_CLIENTAUTH) {
      l += sprintf (str + l, "clientAuth");
   }
   if (flags & EXT_KEY_USAGE_CODESIGNING) {
      l += sprintf (str + l, "codeSigning");
   }
   if (flags & EXT_KEY_USAGE_EMAILPROTECTION) {
      l += sprintf (str + l, "emailProtection");
   }
   if (flags & EXT_KEY_USAGE_TIMESTAMPING) {
      l += sprintf (str + l, "timeStamping");
   }
   if (flags & EXT_KEY_USAGE_MSCODEIND) {
      l += sprintf (str + l, "msCodeInd");
   }
   if (flags & EXT_KEY_USAGE_MSCODECOM) {
      l += sprintf (str + l, "msCodeCom");
   }
   if (flags & EXT_KEY_USAGE_MSCTLSIGN) {
      l += sprintf (str + l, "msCTLSign");
   }
   if (flags & EXT_KEY_USAGE_MSSGC) {
      l += sprintf (str + l, "msSGC");
   }
   if (flags & EXT_KEY_USAGE_MSEFS) {
      l += sprintf (str + l, "msEFS");
   }
   if (flags & EXT_KEY_USAGE_NSSGC) {
      l += sprintf (str + l, "nsSGC");
   }
}

void
_mongoc_x509_add_ext (X509 *x509gen, int type, char *value)
{
   X509_EXTENSION *ext = X509V3_EXT_conf_nid (NULL, NULL, type, value);
   X509_add_ext (x509gen, ext, -1);
}
int
_mongoc_sign_csr (const char *servername, const tls_options *settings)
{
   BIO *out = NULL;
   BIO *x509bio = NULL;
   BIO *cabio;
   EVP_PKEY *capkey = NULL;
   X509 *cax509;
   X509 *x509gen;
   X509_REQ *req = NULL;
   EVP_PKEY *pktmp = NULL;
   ASN1_INTEGER *serial = NULL;
   int pathlen = strlen (servername) + strlen ("certs/.key.pem") + 1;
   char *path = malloc (pathlen);

   snprintf (path, pathlen, "certs/%s.csr.pem", servername);

   cabio = BIO_new_file ("ca.pem", "r");
   capkey = PEM_read_bio_PrivateKey (cabio, NULL, 0, NULL);
   cax509 = PEM_read_bio_X509 (cabio, NULL, 0, NULL);
   if (!capkey) {
      fail ("Cannot create a user certificate: could not read private key from "
            "sslCAFile");
   }
   BIO_free_all (cabio);
   if (!X509_check_private_key (cax509, capkey)) {
      fail ("Public/private keys in sslCAFile do not match");
   }

   // Read cert signing request
   x509bio = BIO_new_file (path, "r");

   req = PEM_read_bio_X509_REQ (x509bio, NULL, NULL, NULL);
   BIO_free_all (x509bio);

   x509gen = X509_new ();
   X509_set_version (x509gen, 2);
   serial = s2i_ASN1_INTEGER (NULL, (char *) "911112");
   X509_set_serialNumber (x509gen, serial);
   X509_set_issuer_name (x509gen, X509_get_subject_name (cax509));

   if (settings->not_before) {
      ASN1_TIME_set (X509_get_notBefore (x509gen),
                     (time_t) settings->not_before);
   } else {
      X509_gmtime_adj (X509_get_notBefore (x509gen), 0);
   }

   if (settings->not_after) {
      ASN1_TIME_set (X509_get_notAfter (x509gen), (time_t) settings->not_after);
   } else {
      X509_time_adj_ex (X509_get_notAfter (x509gen), 365, 0, NULL);
   }

   X509_set_subject_name (x509gen, X509_REQ_get_subject_name (req));

   pktmp = X509_REQ_get_pubkey (req);
   X509_set_pubkey (x509gen, pktmp);
   EVP_PKEY_free (pktmp);


   if (settings->san) {
      _mongoc_x509_add_ext (x509gen, NID_subject_alt_name, settings->san);
   }

   if (settings->basic_constraints) {
      char buf[1024];

      _mongoc_basic_constraints_to_str (settings->basic_constraints,
                                        (char *) &buf);
      _mongoc_x509_add_ext (x509gen, NID_basic_constraints, (char *) buf);
   }

   if (settings->key_usage) {
      char buf[1024];

      _mongoc_key_usage (settings->key_usage, (char *) &buf);
      _mongoc_x509_add_ext (x509gen, NID_key_usage, (char *) buf);
   }

   if (settings->ext_key_usage) {
      char buf[1024];

      _mongoc_ext_key_usage (settings->key_usage, (char *) &buf);
      _mongoc_x509_add_ext (x509gen, NID_ext_key_usage, (char *) buf);
   }

   X509_sign (x509gen, capkey, EVP_sha256 ());

   ASN1_INTEGER_free (serial);

   path[pathlen - 8] = 'k';
   path[pathlen - 7] = 'e';
   path[pathlen - 6] = 'y';

   out = BIO_new_file (path, "ab");
   X509_print (NULL, x509gen);
   if (!PEM_write_bio_X509 (out, x509gen)) {
      fail ("couldn't write new cert");
   }
   BIO_free_all (out);
   free (path);

   return 1;
}

int
_mongoc_generate_certificate_for (const char *servername, tls_options *settings)
{
   int pathlen = strlen (servername) + strlen ("certs/.key.pem") + 1;
   char *path = malloc (pathlen);

   snprintf (path, pathlen, "certs/%s.key.pem", servername);

   _mongoc_generate_csr (servername, settings);
   _mongoc_sign_csr (servername, settings);
   settings->issuerfile = "ca.pem";
   settings->keyfile = path;

   return 1;
}

SSL_CTX *
_mongoc_ssl_make_ctx_for (const char *servername, const SSL_METHOD *method)
{
   SSL_CTX *ssl_ctx;
   tls_options *settings = calloc (sizeof *settings, 1);

   _mongoc_decode_hostname (servername, settings);


   ssl_ctx = SSL_CTX_new (method);
   if (!SSL_CTX_set_cipher_list (ssl_ctx, settings->ciphers)) {
      goto fail;
   }

   if (!settings->keyfile) {
      _mongoc_generate_certificate_for (servername, settings);
   }
   if (!strcmp (settings->keyfile, CERT_GOOD_SERVER)) {
      if (!_mongoc_ssl_setup_certs (ssl_ctx, CERT_CA, CERT_GOOD_SERVER)) {
         goto fail;
      }
   } else {
      if (!_mongoc_ssl_setup_certs (
             ssl_ctx, settings->issuerfile, settings->keyfile)) {
         goto fail;
      }
   }

   fprintf (stderr, "Certificated prepped and good to go!\n");
   _free_tls_options (settings);
   return ssl_ctx;

fail:
   SSL_CTX_free (ssl_ctx);
   free (settings);
   return NULL;
}
static int
_mongoc_ssl_servername_callback (SSL *ssl, int *ad, void *arg)
{
   SSL_CTX *ctx;
   const char *servername;

   if (ssl == NULL) {
      return SSL_TLSEXT_ERR_NOACK;
   }

   servername = SSL_get_servername (ssl, TLSEXT_NAMETYPE_host_name);
   if (!servername) {
      return SSL_TLSEXT_ERR_NOACK;
   }


   fprintf (stderr, "Making CTX for %s\n", servername);
   ctx = _mongoc_ssl_make_ctx_for (servername, SSL_get_ssl_method (ssl));

   if (ctx) {
      SSL_set_SSL_CTX (ssl, ctx);
      return SSL_TLSEXT_ERR_OK;
   }

   return SSL_TLSEXT_ERR_NOACK;
}
SSL_CTX *
mongoc_ssl_ctx_new ()
{
   SSL_CTX *ssl_ctx;
   const SSL_METHOD *method;
   int options;


#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
   method = TLS_server_method ();
#else
   method = SSLv23_server_method ();
#endif

   ssl_ctx = SSL_CTX_new (method);
   if (!ssl_ctx) {
      return NULL;
   }
   options = SSL_OP_ALL | SSL_OP_NO_COMPRESSION | SSL_OP_SINGLE_DH_USE;

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
   SSL_CTX_set_min_proto_version (ssl_ctx, SSL3_VERSION);
#else
   options |= SSL_OP_NO_SSLv2;
#endif

   SSL_CTX_set_options (ssl_ctx, options);

   SSL_CTX_set_tlsext_servername_callback (ssl_ctx,
                                           _mongoc_ssl_servername_callback);

   // SSL_CTX_set_verify (ssl_ctx, SSL_VERIFY_PEER, NULL);
   SSL_CTX_set_mode (ssl_ctx, SSL_MODE_AUTO_RETRY);

   return ssl_ctx;
}

SSL *
mongoc_ssl_new (SSL_CTX *ssl_ctx)
{
   SSL *ssl = NULL;

   ssl = SSL_new (ssl_ctx);

   return ssl;
}

SSL *
mongoc_stream_ssl_wrap (int fd)
{
   SSL_CTX *ssl_ctx = NULL;
   SSL *ssl = NULL;

   ssl_ctx = mongoc_ssl_ctx_new ();
   ssl = mongoc_ssl_new (ssl_ctx);
   SSL_CTX_free (ssl_ctx);

   SSL_set_fd (ssl, fd);
   SSL_set_accept_state (ssl);

   return ssl;
}

int
_socket (int port, cb func)
{
   struct sockaddr_in addr;
   int fd;
   int success;

   fd = socket (AF_INET, SOCK_STREAM, 0);
   if (fd == -1) {
      return 0;
   }

   addr.sin_family = AF_INET;
   addr.sin_addr.s_addr = INADDR_ANY;
   addr.sin_port = htons (port);

   success = func (fd, (struct sockaddr *) &addr, sizeof (addr));
   if (success < 0) {
      return 0;
   }

   return fd;
}

int
_read_write (int polled, SSL *ssl, int fd_ssl, int fd_plain)
{
   char buffer[8192];
   ssize_t size = 0;

   if (polled == fd_ssl) {
      size = SSL_read (ssl, buffer, sizeof (buffer));
      write (fd_plain, buffer, size);
   } else {
      size = recv (fd_plain, buffer, sizeof (buffer), 0);
      SSL_write (ssl, buffer, size);
   }

   return size > 0;
}

void *
worker (void *arg)
{
   worker_config cfg = *(worker_config *) arg;
   int fd_server;
   int n;
   int success;
   int sockets = 2;
   struct pollfd fds[sockets];
   SSL *ssl;

   fd_server = _socket (27017, connect);
   if (!fd_server) {
      perror ("connect failed");
      return (void *) 1;
   }

   _init_openssl ();

   ssl = mongoc_stream_ssl_wrap (cfg.fd_client);
   int ret = SSL_do_handshake (ssl);
   if (ret < 1) {
      /* should the test suite determine if it failed or not? */
      fprintf (stderr, "Handhsake failed\n");
      goto fail;
   }

   fds[0].fd = cfg.fd_client;
   fds[0].events = POLLIN;
   fds[1].fd = fd_server;
   fds[1].events = POLLIN;

   do {
      success = poll (fds, sockets, 1000);

      for (n = 0; n < sockets; ++n) {
         if (fds[n].revents & POLLIN) {
            success = _read_write (fds[n].fd, ssl, cfg.fd_client, fd_server);
         }
      }
   } while (success > 0);

fail:
   SSL_shutdown (ssl);
   SSL_free (ssl);

   close (cfg.fd_client);
   close (fd_server);
   fprintf (stderr, "Worker done\n");
   return (void *) EXIT_SUCCESS;
}

int
main (int argc, char *argv[])
{
   int sd;
   int fd;
   int success;
   worker_config *cfg = calloc (sizeof *cfg, 1);


   if (argc != 3) {
      fprintf (stderr, "usage: %s MY-PORT SERVER-PORT\n", argv[0]);
      return 1;
   }

   sd = _socket (atoi (argv[1]), bind);
   if (!sd) {
      perror ("bind failed");
      return 1;
   }
   cfg->server_port = atoi (argv[2]);

   fprintf (stderr, "Daemon listening to %d\n", atoi (argv[1]));
   fprintf (stderr, "The server will be listening to %d\n", cfg->server_port);
   listen (sd, 42);

   fprintf (stdout, "Ready...\n");
   do {
      pthread_t thread;

      fd = accept (sd, NULL, NULL);
      if (fd < 1) {
         perror ("accept failed");
         break;
      }

      cfg->fd_client = fd;

      success = pthread_create (&thread, NULL, worker, (void *) cfg);
      if (success < 0) {
         perror ("could not create thread");
         return 1;
      }

      pthread_detach (thread);
   } while (1);
   close (sd);

   free (cfg);
   return 0;
}
