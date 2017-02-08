#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <pthread.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


#define CERT_GOOD_SERVER "server.pem"
#define CERT_CA "ca.pem"
#define INTERMEDIATE_CA "intermediate_ca.pem"

// Holds all the TLS options configurable through the hostname.
typedef struct _tls_options {
   // TLS Options
   char *ciphers;       // Acceptable TLS cipher suites
   int tls_versions;    // Acceptable TLS_VERSION_* versions
   int tls_compression; // Enable TLS compression

   // Use hard coded server PEM file
   char *keyfile;

   // Certificate Generation Options
   char *cn;           // CN: Common Name
   char *issuer;       // Signing CA: root, intermediate, unknown
   int64_t not_before; // Not valid before datetime
   int64_t not_after;  // Not valid after datetime
   char **san; // SAN: Subject Alt Names, list of IP Addresses or DNS names
   // Basic Constraints
   int cert_authority; // Is Certificate Authority
   // Key Usage
   int key_cert_sign;     // Key Cert Sign
   int digital_signature; // Digital Signature
   int non_repudiation;   // Non Repudiation
   int key_encipherment;  // Key Encipherment
   int data_encipherment; // Data Encipherment
   // Extended Key Usage
   int server_auth;      // Server Authentication
   int client_auth;      // Client Authentication
   int code_signing;     // Code Signing
   int email_protection; // Email Protection
   int time_stamping;    // Time Stamping
} tls_options;

void
_free_tls_options (tls_options **options_ptr)
{
   if (options_ptr == NULL || *options_ptr == NULL) {
      return;
   }
   tls_options *options = *options_ptr;

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
      for (int i = 0; options->san[i]; i++) {
         free (options->san[i]);
      }
      free (options->san);
   }
   free (options);
   *options_ptr = NULL;
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

int
_mongoc_decode_hostname (const char *servername, tls_options *settings)
{
   if (servername == NULL || settings == NULL) {
      return 0;
   }
   settings->ciphers = "HIGH:!EXPORT:!aNULL@STRENGTH";

   return 1;
}

SSL_CTX *
_mongoc_ssl_make_ctx_for (const char *servername, const SSL_METHOD *method)
{
   SSL_CTX *ssl_ctx;
   tls_options *settings = calloc (sizeof *settings, 1);

   _mongoc_decode_hostname (servername, settings);


   if (!strcmp (servername, "localhost")) {
      ssl_ctx = SSL_CTX_new (method);
      // if (!SSL_CTX_set_cipher_list (ssl_ctx, "EXPORT")) {
      if (!SSL_CTX_set_cipher_list (ssl_ctx, "HIGH:!EXPORT:!aNULL@STRENGTH")) {
         SSL_CTX_free (ssl_ctx);
         return NULL;
      }

      if (!_mongoc_ssl_setup_ca (ssl_ctx, CERT_CA, NULL)) {
         SSL_CTX_free (ssl_ctx);
         return NULL;
      }

      if (!_mongoc_ssl_setup_pem_file (ssl_ctx, CERT_GOOD_SERVER)) {
         SSL_CTX_free (ssl_ctx);
         return NULL;
      }

      fprintf (stderr, "Certificated prepped and good to go!\n");
      return ssl_ctx;
   }

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

typedef int (*cb) (int fd, __CONST_SOCKADDR_ARG, socklen_t addrlen);

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
   int fd_client = *(int *) arg;
   int fd_mongo;
   int n;
   int success;
   int sockets = 2;
   struct pollfd fds[sockets];
   SSL *ssl;

   fd_mongo = _socket (27017, connect);
   if (!fd_mongo) {
      perror ("connect failed");
      return (void *) 1;
   }

   _init_openssl ();

   ssl = mongoc_stream_ssl_wrap (fd_client);
   int ret = SSL_do_handshake (ssl);
   if (ret < 1) {
      /* should the test suite determine if it failed or not? */
      fprintf (stderr, "Handhsake failed\n");
      goto fail;
   }

   fds[0].fd = fd_client;
   fds[0].events = POLLIN;
   fds[1].fd = fd_mongo;
   fds[1].events = POLLIN;

   do {
      success = poll (fds, sockets, 1000);

      for (n = 0; n < sockets; ++n) {
         if (fds[n].revents & POLLIN) {
            success = _read_write (fds[n].fd, ssl, fd_client, fd_mongo);
         }
      }
   } while (success > 0);

fail:
   SSL_shutdown (ssl);
   SSL_free (ssl);

   close (fd_client);
   close (fd_mongo);
   free (arg);
   fprintf (stderr, "Worker done\n");
   return (void *) EXIT_SUCCESS;
}

int
main (int argc, char *argv[])
{
   int sd;
   int fd;
   int *args;
   int success;


   sd = _socket (8888, bind);
   if (!sd) {
      perror ("bind failed");
      return 1;
   }

   listen (sd, 42);

   fprintf (stdout, "Ready...\n");
   do {
      pthread_t thread;

      fd = accept (sd, NULL, NULL);
      if (fd < 1) {
         perror ("accept failed");
         break;
      }

      args = malloc (1);
      *args = fd;

      success = pthread_create (&thread, NULL, worker, (void *) args);
      if (success < 0) {
         perror ("could not create thread");
         return 1;
      }

      pthread_detach (thread);
   } while (1);
   close (sd);

   return 0;
}
