/*
 * Copyright (c) 2016, Saúl Ibarra Corretgé <saghul@gmail.com>
 * Copyright (c) 2012, Ben Noordhuis <info@bnoordhuis.nl>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <uv.h>

#include "queue.h"
#include "pokemon_names.h"


#define SERVER_ADDR "0.0.0.0" // a.k.a. "all interfaces"
#define SERVER_PORT 8000

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct user
{
  QUEUE queue;
  uv_tcp_t handle;
  char id[32];
};

static void *xmalloc(size_t len);
static void fatal(const char *what, int error);
static void unicast(struct user *user, const char *msg);
static void broadcast(const struct user* sender, const char *fmt, ...);
static void make_user_id(struct user *user);
static const char *addr_and_port(struct user *user);
static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
static void on_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf);
static void on_write(uv_write_t *req, int status);
static void on_close(uv_handle_t* handle);
static void on_connection(uv_stream_t* server_handle, int status);

static QUEUE users;

int main(void)
{
  QUEUE_INIT(&users);

  srand(1234);

  int r;

  uv_tcp_t server_handle;
  uv_tcp_init(uv_default_loop(), &server_handle);

  struct sockaddr_in addr;
  uv_ip4_addr(SERVER_ADDR, SERVER_PORT, &addr);

  r = uv_tcp_bind(&server_handle, (const struct sockaddr*) &addr, 0);
  if (r < 0)
    fatal("uv_tcp_bind", r);

  const int backlog = 128;
  r = uv_listen((uv_stream_t*) &server_handle, backlog, on_connection);
  if (r < 0)
    fatal("uv_listen", r);

  printf("Listening at %s:%d\n", SERVER_ADDR, SERVER_PORT);
  uv_run(uv_default_loop(), UV_RUN_DEFAULT);

  return 0;
}

static void on_connection(uv_stream_t* server_handle, int status)
{
  assert(status == 0);
  int r;

  // hurray, a new user!
  struct user *user = xmalloc(sizeof(*user));
  uv_tcp_init(uv_default_loop(), &user->handle);

  r = uv_accept(server_handle, (uv_stream_t*) &user->handle);
  if (r < 0)
    fatal("uv_accept", r);

  // add him to the list of users
  QUEUE_INSERT_TAIL(&users, &user->queue);
  make_user_id(user);

  // now tell everyone, incuding yourself (to know your name!)
  broadcast(NULL, "* A wild %s appeared from %s\n", user->id, addr_and_port(user));

  // start accepting messages from the user
  uv_read_start((uv_stream_t*) &user->handle, on_alloc, on_read);
}

static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
  buf->base = xmalloc(suggested_size);
  buf->len = suggested_size;
}

static void on_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf)
{
  struct user *user = QUEUE_DATA(handle, struct user, handle);

  if (nread == UV_EOF) {
    // user disconnected
    QUEUE_REMOVE(&user->queue);
    uv_close((uv_handle_t*) &user->handle, on_close);
    broadcast(NULL, "* %s fled!\n", user->id);
  } else if (nread > 0) {
    // broadcast message
    broadcast(user, "%s said: %.*s", user->id, (int) nread, buf->base);
  } else {
    fprintf(stderr, "on_read: %s\n", uv_strerror(nread));
  }

  free(buf->base);
}

static void on_write(uv_write_t *req, int status)
{
  free(req);
}

static void on_close(uv_handle_t* handle)
{
  struct user *user = QUEUE_DATA(handle, struct user, handle);
  free(user);
}

static void fatal(const char *what, int error)
{
  fprintf(stderr, "%s: %s\n", what, uv_strerror(error));
  exit(1);
}

static void broadcast(const struct user* sender, const char *fmt, ...)
{
  QUEUE *q;
  char msg[512];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);

  QUEUE_FOREACH(q, &users) {
    struct user *user = QUEUE_DATA(q, struct user, queue);
    if (user != sender) {
      unicast(user, msg);
    }
  }
}

static void unicast(struct user *user, const char *msg)
{
  size_t len = strlen(msg);
  uv_write_t *req = xmalloc(sizeof(*req) + len);
  void *addr = req + 1;
  memcpy(addr, msg, len);
  uv_buf_t buf = uv_buf_init(addr, len);
  uv_write(req, (uv_stream_t*) &user->handle, &buf, 1, on_write);
}

static void make_user_id(struct user *user)
{
  snprintf(user->id, sizeof(user->id), "%s", pokemon_names[rand() % ARRAY_SIZE(pokemon_names)]);
}

static const char *addr_and_port(struct user *user)
{
  int r;
  struct sockaddr_in name;
  int namelen = sizeof(name);

  r = uv_tcp_getpeername(&user->handle, (struct sockaddr*) &name, &namelen);
  if (r < 0)
    fatal("uv_tcp_getpeername", r);

  char addr[16];
  static char buf[32];
  uv_inet_ntop(AF_INET, &name.sin_addr, addr, sizeof(addr));
  snprintf(buf, sizeof(buf), "%s:%d", addr, ntohs(name.sin_port));

  return buf;
}

static void *xmalloc(size_t len)
{
  void *ptr = malloc(len);
  assert(ptr != NULL);
  return ptr;
}
