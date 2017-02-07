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
_read_write (int rfd, int wfd)
{
   char buffer[1024];
   ssize_t size = 0;

   size = recv (rfd, buffer, sizeof (buffer), 0);
   write (wfd, buffer, size);

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

   fd_mongo = _socket (27017, connect);
   if (!fd_mongo) {
      perror ("connect failed");
      return (void *) 1;
   }

   fds[0].fd = fd_client;
   fds[0].events = POLLIN;
   fds[1].fd = fd_mongo;
   fds[1].events = POLLIN;

   do {
      success = poll (fds, sockets, 10);

      for (n = 0; n < sockets; ++n) {
         if (fds[n].revents & POLLIN) {
            int fd = fds[n].fd == fd_mongo ? fd_client : fd_mongo;
            success = _read_write (fds[n].fd, fd);
         }
      }
   } while (success > 0);

   close (fd_client);
   close (fd_mongo);
   free (arg);
   return (void *) EXIT_SUCCESS;
}

int
main (int argc, char *argv[])
{
   int sd;
   int fd;
   int *args;
   struct sockaddr_in addr;
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
