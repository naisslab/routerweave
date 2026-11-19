/* Native IPv4 PCAP -> structured FiLM inputs. No Python at runtime.
 * Semantic reference: device_connection_inputs, device_flow_roles,
 * device_visible_headers, device_service_context, service_behavior_inputs.
 * Bounded resources fail explicitly rather than silently truncating inputs.
 */
#include "service_rules.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <regex.h>
#include <stdint.h>
#define RF_FLOWS 32768
#define RF_KEYS 65536
#define RF_NAMES 32768
#define RF_STREAM_LIMIT 131072
#define RF_OWNER 65535u
#define RF_ROLE (63u << 16)
typedef struct {
  double t, gap;
  unsigned char ttl, tcp_flags, header_valid;
  unsigned short tcp_window;
  int length, wire, in, flow, transport_flow, proto, payload, energy, order;
  unsigned bits, quality, legacy;
#ifdef RF_NAME_SKETCH
  uint64_t name_sketch[2];
#endif
} RFPacket;
typedef struct {
  unsigned ip;
  int proto, local, remote, id, syn;
  unsigned seq;
} RFKey;
typedef struct {
  unsigned next;
  int active, closed, bytes, n, h;
  unsigned char *buf, *hello;
} RFStream;
typedef struct {
  int host, target;
  unsigned ip;
  double until;
} RFRecord;
typedef struct {
  double t;
  int flow, kind, in, names[32], nn, mime, order;
  RFRecord *rr;
  int nr;
} RFEvent;
typedef struct {
  unsigned owners, roles, mime;
  int known, unknown, tls, http;
#ifdef RF_NAME_SKETCH
  uint64_t name_sketch[2];
#endif
} RFDirect;
typedef struct {
  int http_closed, tls_closed;
} RFClosed;
typedef struct {
  RFClosed *closed;
  RFPacket *p;
  int np, pcap;
  RFKey *keys;
  int nk, reused, maxflow;
  RFStream *streams;
  RFEvent *ev;
  int ne, ecap;
  char (*names)[256];
  unsigned *namebits;
  int nn;
#ifdef RF_NAME_SKETCH
  uint64_t (*name_sketch)[2];
#endif
  regex_t role_re[6];
  unsigned *peer;
  double previous[2];
  unsigned device;
  int dns, tls, http;
  double first, last;
  RFRecord *records;
  int nr, associated, processed_events;
  RFDirect *direct;
  double association_previous[2];
  int packet_serial, event_serial;
  unsigned long long released_empty_buffers, released_empty_capacity_bytes;
} RFCapture;
static void rf_fail(const char *s) {
  fprintf(stderr, "router features: %s\n", s);
  exit(1);
}
static void *rf_alloc(size_t n, size_t s) {
  void *p = calloc(n ? n : 1, s);
  if (!p)
    rf_fail("out of memory");
  return p;
}
static unsigned rf_u16(const unsigned char *p) {
  return ((unsigned)p[0] << 8) | p[1];
}
static unsigned rf_u32(const unsigned char *p) {
  return ((unsigned)p[0] << 24) | ((unsigned)p[1] << 16) |
         ((unsigned)p[2] << 8) | p[3];
}
#ifdef RF_NAME_SKETCH
static uint64_t rf_suffix_sketch(const char *name, int labels) {
  const char *start = name;
  int count = 1;
  size_t length = strlen(name);
  if (!length)
    return 0;
  for (size_t i = 0; i < length; i++)
    if ((unsigned char)name[i] >= 128)
      return 0;
  for (size_t i = length; i > 0; i--)
    if (name[i - 1] == '.' && ++count > labels) {
      start = name + i;
      break;
    }
  uint32_t code = 2166136261u ^ (unsigned)labels;
  for (const unsigned char *p = (const unsigned char *)start; *p; p++)
    code = (code ^ *p) * 16777619u;
  code ^= code >> 16;
  return UINT64_C(1) << (code & 63u);
}
#endif
static int rf_suffix(const char *s, const char *d) {
  size_t n = strlen(s), m = strlen(d);
  return n >= m && !strcmp(s + n - m, d) && (n == m || s[n - m - 1] == '.');
}
static int rf_name(RFCapture *c, const char *s) {
  char name[256];
  size_t n = strlen(s);
  if (n > 253)
    rf_fail("hostname exceeds contract");
  while (n && s[n - 1] == '.')
    n--;
  for (size_t i = 0; i < n; i++)
    name[i] = (char)tolower((unsigned char)s[i]);
  name[n] = 0;
  for (int i = 0; i < c->nn; i++)
    if (!strcmp(c->names[i], name))
      return i;
  if (c->nn == RF_NAMES)
    rf_fail("hostname capacity reached");
  int id = c->nn++;
  strcpy(c->names[id], name);
#ifdef RF_NAME_SKETCH
  c->name_sketch[id][0] = rf_suffix_sketch(name, 2);
  c->name_sketch[id][1] = rf_suffix_sketch(name, 3);
#endif
  unsigned bits = 0;
  size_t longest = 0;
  for (size_t i = 0; i < sizeof(rf_domains) / sizeof(rf_domains[0]); i++)
    if (rf_suffix(name, rf_domains[i].domain)) {
      bits |= 1u << rf_domains[i].group;
      size_t m = strlen(rf_domains[i].domain);
      if (m > longest)
        longest = m;
    }
  char prefix[256];
  strcpy(prefix, name);
  if (longest) {
    n -= longest;
    while (n && prefix[n - 1] == '.')
      n--;
    prefix[n] = 0;
  }
  for (int i = 0; i < 6; i++)
    if (!regexec(&c->role_re[i], prefix, 0, NULL, 0))
      bits |= 1u << (16 + i);
  for (size_t i = 0; i < sizeof(rf_role_domains) / sizeof(rf_role_domains[0]);
       i++)
    if (rf_suffix(name, rf_role_domains[i].domain))
      bits |= 1u << rf_role_domains[i].group;
  c->namebits[id] = bits;
  return id;
}
static void rf_init(RFCapture *c, const char *ip) {
  memset(c, 0, sizeof(*c));
  if (inet_pton(AF_INET, ip, &c->device) != 1)
    rf_fail("invalid IPv4");
  c->keys = rf_alloc(RF_KEYS, sizeof(RFKey));
  for (int i = 0; i < RF_KEYS; i++)
    c->keys[i].id = -1;
  c->closed = rf_alloc(RF_FLOWS * 2, sizeof(RFClosed));
  c->streams = rf_alloc(RF_FLOWS * 2, sizeof(RFStream));
  c->peer = rf_alloc(RF_FLOWS, sizeof(unsigned));
  c->names = rf_alloc(RF_NAMES, 256);
  c->namebits = rf_alloc(RF_NAMES, sizeof(unsigned));
  c->previous[0] = c->previous[1] = -1;
#ifdef RF_NAME_SKETCH
  c->name_sketch = rf_alloc(RF_NAMES, sizeof(*c->name_sketch));
#endif
  c->association_previous[0] = c->association_previous[1] = -1;
  for (int i = 0; i < 6; i++)
    if (regcomp(&c->role_re[i], rf_role_patterns[i], REG_EXTENDED | REG_NOSUB))
      rf_fail("role regex");
}
static int rf_dn(RFCapture *c, const unsigned char *b, int n, int *at,
                 int depth) {
  if (depth > 20)
    return -1;
  int p = *at, stop = -1, j = 0;
  char name[256];
  for (int steps = 0; steps < 256; steps++) {
    if (p >= n)
      return -1;
    int len = b[p++];
    if (!len) {
      if (stop < 0)
        stop = p;
      name[j] = 0;
      *at = stop;
      return rf_name(c, name);
    }
    if ((len & 192) == 192) {
      if (p >= n)
        return -1;
      int next = ((len & 63) << 8) | b[p++];
      if (stop < 0)
        stop = p;
      int id = rf_dn(c, b, n, &next, depth + 1);
      if (id < 0)
        return -1;
      size_t k = strlen(c->names[id]);
      if (j + (j ? 1 : 0) + k > 253)
        return -1;
      if (j)
        name[j++] = '.';
      memcpy(name + j, c->names[id], k + 1);
      *at = stop;
      return rf_name(c, name);
    }
    if (len > 63 || p + len > n || j + (j ? 1 : 0) + len > 253)
      return -1;
    if (j)
      name[j++] = '.';
    for (int k = 0; k < len; k++) {
      if (b[p] >= 128)
        return -1;
      name[j++] = (char)tolower(b[p++]);
    }
  }
  return -1;
}
static void rf_event(RFCapture *c, RFEvent *e) {
  if (c->ne == c->ecap) {
    c->ecap = c->ecap ? c->ecap * 2 : 1024;
    if (c->ecap > 262144)
      rf_fail("event capacity");
    c->ev = realloc(c->ev, c->ecap * sizeof(RFEvent));
    if (!c->ev)
      rf_fail("events allocation");
  }
  e->order = c->event_serial++;
  c->ev[c->ne++] = *e;
  if (e->kind == 0)
    c->dns++;
  else if (e->kind == 1)
    c->tls++;
  else
    c->http++;
}
static void rf_dns(RFCapture *c, const unsigned char *b, int n, double t,
                   int flow, int in, int aliases) {
  if (n < 12)
    return;
  unsigned flags = rf_u16(b + 2), nq = rf_u16(b + 4), na = rf_u16(b + 6),
           nr = na + rf_u16(b + 8) + rf_u16(b + 10);
  if (nq > 32 || nr > 512)
    return;
  RFEvent e = {0};
  e.t = t;
  e.flow = flow;
  e.in = in;
  e.rr = rf_alloc(nr, sizeof(RFRecord));
  int p = 12;
  for (unsigned i = 0; i < nq; i++) {
    int h = rf_dn(c, b, n, &p, 0);
    if (h < 0 || p + 4 > n)
      goto bad;
    e.names[e.nn++] = h;
    p += 4;
  }
  for (unsigned i = 0; i < nr; i++) {
    int h = rf_dn(c, b, n, &p, 0);
    if (h < 0 || p + 10 > n)
      goto bad;
    int type = rf_u16(b + p), cls = rf_u16(b + p + 2), len = rf_u16(b + p + 8);
    unsigned ttl = rf_u32(b + p + 4);
    p += 10;
    if (p + len > n)
      goto bad;
    if (i < na && cls == 1 && in && (flags & 0x8000) && !(flags & 0x20f)) {
      RFRecord r = {0};
      r.host = h;
      r.target = -1;
      r.until = t + ttl;
      if (type == 1 && len == 4) {
        memcpy(&r.ip, b + p, 4);
        e.rr[e.nr++] = r;
      } else if (type == 5 && aliases) {
        int pos = p;
        r.target = rf_dn(c, b, n, &pos, 0);
        if (r.target < 0 || pos > p + len)
          goto bad;
        e.rr[e.nr++] = r;
      }
    }
    p += len;
  }
  rf_event(c, &e);
  return;
bad:
  free(e.rr);
}
static int rf_host(RFCapture *c, RFEvent *e, const unsigned char *s, int n) {
  if (n > 253 || e->nn == 32)
    return 0;
  char b[256];
  for (int i = 0; i < n; i++) {
    if (s[i] >= 128)
      return 0;
    b[i] = (char)s[i];
  }
  b[n] = 0;
  e->names[e->nn++] = rf_name(c, b);
  return 1;
}
static void rf_hello(RFCapture *c, const unsigned char *b, int n, int kind,
                     double t, int flow, int in) {
  if ((kind != 1 && kind != 2) || n < 38)
    return;
  int p = 35 + b[34];
  if (p > n)
    return;
  if (kind == 1) {
    if (p + 2 > n)
      return;
    int len = rf_u16(b + p);
    p += 2;
    if (!len || len % 2 || p + len >= n)
      return;
    p += len;
    p += 1 + b[p];
  } else
    p += 3;
  if (p > n)
    return;
  RFEvent e = {0};
  e.t = t;
  e.flow = flow;
  e.in = in;
  e.kind = 1;
  if (p < n) {
    if (p + 2 > n)
      return;
    int stop = p + 2 + rf_u16(b + p);
    p += 2;
    if (stop != n)
      return;
    while (p < stop) {
      if (p + 4 > stop)
        return;
      int type = rf_u16(b + p), len = rf_u16(b + p + 2);
      p += 4;
      if (p + len > stop)
        return;
      if (type == 0 && kind == 1) {
        if (len < 2 || rf_u16(b + p) != len - 2)
          return;
        int j = p + 2;
        while (j < p + len) {
          if (j + 3 > p + len)
            return;
          int nt = b[j], sz = rf_u16(b + j + 1);
          j += 3;
          if (j + sz > p + len)
            return;
          if (nt == 0 && !rf_host(c, &e, b + j, sz))
            return;
          j += sz;
        }
      }
      if (type == 16) {
        if (len < 2 || rf_u16(b + p) != len - 2)
          return;
        int j = p + 2;
        while (j < p + len) {
          int sz = b[j++];
          if (j + sz > p + len)
            return;
          for (int k = 0; k < sz; k++)
            if (b[j + k] >= 128)
              return;
          j += sz;
        }
      }
      p += len;
    }
  }
  rf_event(c, &e);
}
static int rf_http(RFCapture *c, const unsigned char *b, int n, double t,
                   int flow, int in) {
  const char *prefix[] = {"GET ", "POST ",    "HEAD ",
                          "PUT ", "OPTIONS ", "HTTP/1."};
  int valid = 0;
  for (int i = 0; i < 6; i++)
    if (n >= (int)strlen(prefix[i]) && !memcmp(b, prefix[i], strlen(prefix[i])))
      valid = 1;
  if (!valid)
    return 0;
  int end = -1;
  for (int i = 0; i + 3 < n && i <= 32768; i++)
    if (!memcmp(b + i, "\r\n\r\n", 4)) {
      end = i;
      break;
    }
  if (end < 0)
    return 0;
  RFEvent e = {0};
  e.t = t;
  e.flow = flow;
  e.in = in;
  e.kind = 2;
  int p = 0;
  while (p < end) {
    int q = p;
    while (q < end && !(b[q] == '\r' && b[q + 1] == '\n'))
      q++;
    int colon = p;
    while (colon < q && b[colon] != ':')
      colon++;
    if (colon < q) {
      char key[64];
      int kn = colon - p;
      if (kn < 64) {
        for (int i = 0; i < kn; i++)
          key[i] = (char)tolower(b[p + i]);
        key[kn] = 0;
        int a = colon + 1, z = q;
        while (a < z && isspace(b[a]))
          a++;
        while (z > a && isspace(b[z - 1]))
          z--;
        if (!strcmp(key, "host")) {
          int k = a;
          while (k < z && b[k] != ':')
            k++;
          e.nn = 0;
          if (!rf_host(c, &e, b + a, k - a))
            return 0;
        }
        if (!strcmp(key, "content-type")) {
          char mime[128];
          int k = 0;
          while (a < z && b[a] != ';' && k < 127)
            mime[k++] = (char)tolower(b[a++]);
          mime[k] = 0;
          if (!strncmp(mime, "audio/", 6))
            e.mime = 1u << 22;
          else if (!strncmp(mime, "video/", 6))
            e.mime = 1u << 23;
          else if (!strncmp(mime, "image/", 6))
            e.mime = 1u << 24;
          else if (!strcmp(mime, "application/json"))
            e.mime = 1u << 25;
          else if (!strncmp(mime, "text/", 5))
            e.mime = 1u << 26;
        }
      }
    }
    p = q + 2;
  }
  rf_event(c, &e);
  return 1;
}
/* A stream has one shared contiguous prefix; HTTP and TLS states close
 * independently. */

static void rf_stream(RFCapture *c, int flow, int in, unsigned seq, int flags,
                      const unsigned char *b, int n, int declared, int dns,
                      double t) {
  int captured = n;
  int id = flow * 2 + in;
  RFStream *s = c->streams + id;
  RFClosed *closed = c->closed + id;
  if ((flags & 2) && !s->active) {
    s->active = 1;
    s->next = seq + 1;
  }
  if (!s->active || s->closed)
    return;
  seq += (flags & 2) != 0;
  if (n) {
    unsigned delta = seq - s->next;
    if (delta >= 0x80000000u) {
      unsigned overlap = s->next - seq;
      if (overlap >= (unsigned)n)
        n = 0;
      else {
        b += overlap;
        n -= (int)overlap;
      }
    } else if (delta) {
      s->closed = 1;
      goto finish;
    }
    s->next += n;
    s->bytes += n;
    if (s->bytes > RF_STREAM_LIMIT) {
      s->closed = 1;
      goto finish;
    }
    if (!s->buf)
      s->buf = rf_alloc(RF_STREAM_LIMIT + 1, 1);
    memcpy(s->buf + s->n, b, n);
    s->n += n;
    if (dns) {
      while (s->n >= 2) {
        int size = rf_u16(s->buf);
        if (size < 12) {
          s->closed = 1;
          break;
        }
        if (s->n < size + 2)
          break;
        rf_dns(c, s->buf + 2, size, t, flow, in, 0);
        s->n -= size + 2;
        memmove(s->buf, s->buf + size + 2, s->n);
      }
    } else {
      /* HTTP buffer must persist separately after TLS consumes its records. */
      if (!closed->http_closed) {
        if (rf_http(c, s->buf, s->n, t, flow, in) || s->bytes > 32768)
          closed->http_closed = 1;
      }
      if (!closed->tls_closed) {
        while (s->n >= 5) {
          if (s->buf[0] != 22 || s->buf[1] != 3) {
            closed->tls_closed = 1;
            break;
          }
          int size = rf_u16(s->buf + 3);
          if (size > 18432) {
            closed->tls_closed = 1;
            break;
          }
          if (s->n < size + 5)
            break;
          /* A TLS prefix cannot be HTTP, so closing HTTP here changes no
           * events. */
          closed->http_closed = 1;
          if (!s->hello)
            s->hello = rf_alloc(RF_STREAM_LIMIT, 1);
          if (s->h + size > RF_STREAM_LIMIT) {
            closed->tls_closed = 1;
            break;
          }
          memcpy(s->hello + s->h, s->buf + 5, size);
          s->h += size;
          s->n -= size + 5;
          memmove(s->buf, s->buf + size + 5, s->n);
          while (s->h >= 4) {
            int kind = s->hello[0],
                len = ((int)s->hello[1] << 16) | rf_u16(s->hello + 2);
            if (len > 65536) {
              closed->tls_closed = 1;
              break;
            }
            if (s->h < len + 4)
              break;
            rf_hello(c, s->hello + 4, len, kind, t, flow, in);
            s->h -= len + 4;
            memmove(s->hello, s->hello + len + 4, s->h);
          }
          if (closed->tls_closed)
            break;
        }
      }
      s->closed = closed->http_closed && closed->tls_closed;
    }
  }
  if (captured < declared)
    s->closed = 1;
finish:
  if (s->closed) {
    free(s->buf);
    free(s->hello);
    s->buf = s->hello = NULL;
  } else {
    if (s->buf && !s->n) {
      free(s->buf);
      s->buf = NULL;
      c->released_empty_buffers++;
      c->released_empty_capacity_bytes += RF_STREAM_LIMIT + 1;
    }
    if (s->hello && !s->h) {
      free(s->hello);
      s->hello = NULL;
      c->released_empty_buffers++;
      c->released_empty_capacity_bytes += RF_STREAM_LIMIT;
    }
  }
}
static int rf_flow(RFCapture *c, unsigned ip, int proto, int local, int remote,
                   int opening, unsigned seq) {
  unsigned hash = (ip * 16777619u) ^ ((unsigned)local * 31u) ^
                  ((unsigned)remote * 131u) ^ (unsigned)proto;
  int pos = hash & (RF_KEYS - 1);
  while (c->keys[pos].id >= 0) {
    RFKey *k = c->keys + pos;
    if (k->ip == ip && k->proto == proto && k->local == local &&
        k->remote == remote)
      break;
    pos = (pos + 1) & (RF_KEYS - 1);
  }
  RFKey *k = c->keys + pos;
  int fresh = k->id < 0;
  /* Match the frozen Python loader's identifiers, including its reused-tuple
   * convention. */
  if (fresh || (opening && (!k->syn || k->seq != seq))) {
    int id = c->nk + c->reused;
    if (id >= RF_FLOWS || c->nk >= RF_KEYS / 2)
      rf_fail("connection capacity reached");
    if (fresh)
      c->nk++;
    if (k->syn)
      c->reused++;
    k->id = id;
    k->ip = ip;
    k->proto = proto;
    k->local = local;
    k->remote = remote;
    if (id >= c->maxflow)
      c->maxflow = id + 1;
    c->peer[id] = ip;
  }
  if (opening) {
    k->syn = 1;
    k->seq = seq;
  }
  return k->id;
}
static int rf_event_compare(const void *a, const void *b) {
  const RFEvent *x = a, *y = b;
  return x->t < y->t ? -1 : x->t > y->t ? 1 : x->order - y->order;
}
static int rf_packet_compare(const void *a, const void *b) {
  const RFPacket *x = a, *y = b;
  return x->t < y->t ? -1 : x->t > y->t ? 1 : x->order - y->order;
}
static void rf_ingest(RFCapture *c, const unsigned char *frame, unsigned cap,
                      unsigned wire, double t, unsigned link) {
  do {
    int off, ether;
    if (link == 1) {
      if (cap < 14)
        continue;
      off = 14;
      ether = rf_u16(frame + 12);
      while (ether == 0x8100 || ether == 0x88a8 || ether == 0x9100) {
        if (cap < (unsigned)off + 4)
          rf_fail("short VLAN");
        ether = rf_u16(frame + off + 2);
        off += 4;
      }
    } else if (link == 113) {
      if (cap < 16)
        continue;
      off = 16;
      ether = rf_u16(frame + 14);
    } else if (link == 276) {
      if (cap < 20)
        continue;
      off = 20;
      ether = rf_u16(frame);
    } else
      rf_fail("unsupported linktype");
    if (ether != 0x0800 || cap < (unsigned)off + 20)
      continue;
    const unsigned char *ip = frame + off;
    int ihl = (ip[0] & 15) * 4, len = rf_u16(ip + 2), proto = ip[9];
    if (ip[0] >> 4 != 4)
      continue;
    if (ihl < 20 || cap < (unsigned)(off + ihl) || len < ihl)
      rf_fail("invalid IPv4 header");
    unsigned src, dst;
    memcpy(&src, ip + 12, 4);
    memcpy(&dst, ip + 16, 4);
    if (src != c->device && dst != c->device)
      continue;
    int in = dst == c->device;
    if (c->np == c->pcap) {
      c->pcap = c->pcap ? c->pcap * 2 : 65536;
      if (c->pcap > 2097152)
        rf_fail("packet capacity reached");
      c->p = realloc(c->p, c->pcap * sizeof(RFPacket));
      if (!c->p)
        rf_fail("packet allocation");
    }
    RFPacket *p = c->p + c->np++;
    memset(p, 0, sizeof(*p));
    p->t = t;
    p->length = len;
    p->wire = wire;
    p->in = in;
    p->proto = proto;
    p->flow = p->transport_flow = -1;
    p->quality = 1u << 5;
    p->ttl = ip[8];
    p->order = c->packet_serial++;
    p->gap = c->previous[in] < 0 ? -1 : t - c->previous[in];
    c->previous[in] = t;
    if (c->np == 1)
      c->first = t;
    c->last = t;
    p->energy = (((link == 1 && off == 14) || link == 113) &&
                 cap >= (unsigned)(off + ihl + 8) &&
                 (proto == 6 || proto == 17) && !(rf_u16(ip + 6) & 0x1fff) &&
                 (proto != 6 || (cap >= (unsigned)(off + ihl + 20) &&
                                 ((ip[ihl + 12] >> 4) * 4 >= 20))));
    if (proto != 6 && proto != 17)
      continue;
    int sp = 0, dp = 0, valid = 0, payload = 0, flags = 0,
        th = proto == 6 ? 20 : 8;
    unsigned seq = 0;
    const unsigned char *tr = ip + ihl;
    if (!(rf_u16(ip + 6) & 0x3fff) && cap >= (unsigned)(off + ihl + th)) {
      sp = rf_u16(tr);
      dp = rf_u16(tr + 2);
      if (proto == 6) {
        th = (tr[12] >> 4) * 4;
        if (th >= 20 && len >= ihl + th) {
          valid = 1;
          payload = len - ihl - th;
          flags = tr[13];
          seq = rf_u32(tr + 4);
        }
      } else {
        int ulen = rf_u16(tr + 4);
        if (ulen >= 8 && ulen <= len - ihl) {
          valid = 1;
          payload = ulen - 8;
        }
      }
    }
    int flow =
        rf_flow(c, in ? src : dst, proto, in ? dp : sp, in ? sp : dp,
                valid && proto == 6 && (flags & 2) && !(flags & 16), seq);
    p->header_valid = valid && proto == 6;
    p->tcp_flags = flags;
    p->tcp_window = (valid && proto == 6) ? rf_u16(tr + 14) : 0;
    p->transport_flow = flow;
    if (!valid)
      continue;
    p->flow = flow;
    p->payload = payload;
    int captured = (int)cap - off - ihl - th;
    if (captured < 0)
      captured = 0;
    if (captured > payload)
      captured = payload;
    if (proto == 17 && (sp == 53 || dp == 53))
      rf_dns(c, tr + th, captured, t, flow, in, 1);
    if (proto == 6)
      rf_stream(c, flow, in, seq, flags, tr + th, captured, payload,
                sp == 53 || dp == 53, t);
  } while (0);
}
static void rf_associate(RFCapture *c) {
  int sorted = 1;
  for (int i = c->associated + 1; i < c->np; i++)
    if (c->p[i].t < c->p[i - 1].t)
      sorted = 0;
  if (!sorted)
    qsort(c->p + c->associated, c->np - c->associated, sizeof(RFPacket),
          rf_packet_compare);
  sorted = 1;
  for (int i = c->processed_events + 1; i < c->ne; i++)
    if (c->ev[i].t < c->ev[i - 1].t)
      sorted = 0;
  if (!sorted)
    qsort(c->ev + c->processed_events, c->ne - c->processed_events,
          sizeof(RFEvent), rf_event_compare);
  if (!c->records)
    c->records = rf_alloc(65536, sizeof(RFRecord));
  if (!c->direct)
    c->direct = rf_alloc(RF_FLOWS, sizeof(RFDirect));
  RFRecord *records = c->records;
  int nr = c->nr;
  size_t capacity = 65536;
  RFDirect *direct = c->direct;
  int ev = c->processed_events;
  for (int i = c->associated; i < c->np; i++) {
    RFPacket *p = c->p + i;
    if (c->association_previous[p->in] > p->t)
      rf_fail("late packet behind processed stream watermark");
    p->gap = c->association_previous[p->in] < 0
                 ? -1
                 : p->t - c->association_previous[p->in];
    c->association_previous[p->in] = p->t;
    while (ev < c->ne && c->ev[ev].t <= p->t) {
      RFEvent *e = c->ev + ev++;
      if (e->kind == 0) {
        for (int j = 0; j < e->nr; j++) {
          RFRecord r = e->rr[j];
          int k;
          for (k = 0; k < nr; k++)
            if (records[k].host == r.host && records[k].target == r.target &&
                records[k].ip == r.ip)
              break;
          if (k == nr) {
            if ((size_t)nr == capacity)
              rf_fail("DNS record capacity");
            nr++;
          }
          records[k] = r;
        }
      } else {
        RFDirect *d = direct + e->flow;
        for (int j = 0; j < e->nn; j++) {
          int h = e->names[j];
          if (!c->names[h][0])
            continue;
          unsigned b = c->namebits[h];
          d->owners |= b & RF_OWNER;
          d->roles |= b & RF_ROLE;
          if (b & RF_OWNER)
            d->known = 1;
          else
            d->unknown = 1;
          if (e->kind == 1)
            d->tls = 1;
          else
            d->http = 1;
#ifdef RF_NAME_SKETCH
          d->name_sketch[0] |= c->name_sketch[h][0];
          d->name_sketch[1] |= c->name_sketch[h][1];
#endif
        }
        if (e->mime)
          d->mime = e->mime;
      }
    }
    if (p->transport_flow < 0)
      continue;
    unsigned owners = 0, roles = 0, intersection = RF_OWNER;
    int candidates = 0, unknown = 0;
    unsigned peer = c->peer[p->transport_flow];
#ifdef RF_NAME_SKETCH
    uint64_t name_sketch[2] = {0, 0};
#endif
    for (int r = 0; r < nr; r++)
      if (records[r].target < 0 && records[r].ip == peer &&
          records[r].until > p->t) {
        int hosts[1024], nh = 1;
        hosts[0] = records[r].host;
        unsigned b = c->namebits[hosts[0]];
        int from = 0, to = 1;
        for (int depth = 0; depth < 16 && from < to; depth++) {
          for (int j = from; j < to; j++)
            for (int a = 0; a < nr; a++)
              if (records[a].target == hosts[j] && records[a].until > p->t) {
                int h = records[a].host, k;
                for (k = 0; k < nh; k++)
                  if (hosts[k] == h)
                    break;
                if (k == nh) {
                  if (nh == 1024)
                    rf_fail("CNAME expansion capacity");
                  hosts[nh++] = h;
                  b |= c->namebits[h];
                }
              }
          from = to;
          to = nh;
        }
        candidates++;
        owners |= b & RF_OWNER;
        intersection &= b & RF_OWNER;
        roles |= b & RF_ROLE;
        if (!(b & RF_OWNER))
          unknown = 1;
#ifdef RF_NAME_SKETCH
        for (int j = 0; j < nh; j++) {
          name_sketch[0] |= c->name_sketch[hosts[j]][0];
          name_sketch[1] |= c->name_sketch[hosts[j]][1];
        }
#endif
      }
    RFDirect *d = direct + p->transport_flow;
    unsigned legacy_owner = (d->unknown ? 0 : d->owners),
             legacy_role = d->roles;
    /* Legacy owner resolver intersects per-name owners. Multiple owners imply
     * zero. */
    if (__builtin_popcount(legacy_owner) > 1)
      legacy_owner = 0;
    p->legacy =
        (legacy_owner ? legacy_owner : (candidates ? intersection : 0)) |
        (legacy_role ? legacy_role : roles) | d->mime;
    if (p->flow < 0)
      continue;
    int associated = candidates > 0;
    if (d->known || d->unknown) {
      owners = d->owners;
      roles = d->roles;
      unknown = d->unknown;
      associated = 1;
    }
#ifdef RF_NAME_SKETCH
    for (int j = 0; j < 2; j++)
      p->name_sketch[j] =
          (d->known || d->unknown) ? d->name_sketch[j] : name_sketch[j];
#endif
    int ambiguous = __builtin_popcount(owners) > 1 || (owners && unknown);
    if (ambiguous)
      owners = 0;
    p->bits = owners | roles | d->mime;
    p->quality = (candidates > 0) | ((unsigned)d->tls << 1) |
                 ((unsigned)d->http << 2) | ((owners != 0) << 3) |
                 ((associated && !owners && !ambiguous) << 4) |
                 ((!associated) << 5) | (ambiguous << 6) | ((roles != 0) << 7) |
                 ((d->mime != 0) << 8);
  }
  c->nr = nr;
  c->associated = c->np;
  c->processed_events = ev;
}
/* Discard old packet/event observations, retaining causal DNS and connection
 * state. */
static void rf_prune(RFCapture *c, double before) {
  int n = 0;
  while (n < c->associated && c->p[n].t < before)
    n++;
  if (n) {
    memmove(c->p, c->p + n, (c->np - n) * sizeof(RFPacket));
    c->np -= n;
    c->associated -= n;
  }
  n = 0;
  while (n < c->processed_events && c->ev[n].t < before) {
    free(c->ev[n].rr);
    n++;
  }
  if (n) {
    memmove(c->ev, c->ev + n, (c->ne - n) * sizeof(RFEvent));
    c->ne -= n;
    c->processed_events -= n;
  }
  int k = 0;
  for (int i = 0; i < c->nr; i++)
    if (c->records[i].until > before)
      c->records[k++] = c->records[i];
  c->nr = k;
}
static const double rf_sizes[] = {64, 100, 200, 400, 800, 1200, 1500, 3000},
                    rf_gaps[] = {.001, .01, .1, 1, 5, 10, 30};
static int rf_bucket(double x, const double *edges, int n) {
  int i = 0;
  while (i < n && x >= edges[i])
    i++;
  return i;
}
static int rf_cmp(const void *a, const void *b) {
  double x = *(const double *)a, y = *(const double *)b;
  return x < y ? -1 : x > y;
}
static double rf_quantile(double *x, int n, double q) {
  if (!n)
    return 0;
  double at = (n - 1) * q;
  int i = (int)at;
  return x[i] + (at - i) * (x[i + 1 < n ? i + 1 : i] - x[i]);
}
typedef struct {
  int n;
  float *device, *attr, *temporal, context[380], header[40];
  double raw_context[380], owners[16];
} RFInput;
static void rf_extract_length(RFCapture *c, double start, double min_time,
                              int seconds, const double *norm, RFInput *out) {
  if (seconds < 1 || seconds > 90 || min_time < start ||
      min_time >= start + seconds)
    rf_fail("invalid recent observation start");
  memset(out, 0, sizeof(*out));
  int lo = 0, hi = c->np;
  while (lo < hi) {
    int m = (lo + hi) / 2;
    if (c->p[m].t < min_time)
      lo = m + 1;
    else
      hi = m;
  }
  int first = lo, last = first;
  while (last < c->np && c->p[last].t < start + seconds)
    last++;
  int *count = rf_alloc(c->maxflow, sizeof(int)),
      *map = rf_alloc(c->maxflow, sizeof(int));
  double total = 0, assigned = 0, dev[3600] = {0};
  int seen_direction[2] = {0, 0};
  for (int i = first; i < last; i++) {
    RFPacket *p = c->p + i;
    total += p->length;
    if (p->flow >= 0) {
      count[p->flow]++;
      assigned += p->length;
    }
    int bin = (int)floor(p->t - start), off = bin * 40 + p->in * 20;
    dev[off]++;
    dev[off + 1] += p->length;
    dev[off + 2] += p->proto == 6;
    dev[off + 3 + rf_bucket(p->length, rf_sizes, 8)]++;
    if (p->gap >= 0 &&
        ((seconds == 90 && min_time == start) || seen_direction[p->in]))
      dev[off + 12 + rf_bucket(p->gap, rf_gaps, 7)]++;
    seen_direction[p->in] = 1;
  }
  for (int f = 0; f < c->maxflow; f++)
    map[f] = count[f] ? out->n++ : -1;
  out->device = rf_alloc((size_t)seconds * 40, sizeof(float));
  out->attr = rf_alloc(out->n * 16, sizeof(float));
  out->temporal = rf_alloc((size_t)out->n * seconds * 2, sizeof(float));
  for (int i = 0; i < seconds * 40; i++)
    out->device[i] =
        (float)((log1p(dev[i]) - norm[i % 40]) / norm[40 + i % 40]);
  int *offset = rf_alloc(c->maxflow + 1, sizeof(int)),
      *cursor = rf_alloc(c->maxflow, sizeof(int));
  for (int f = 0; f < c->maxflow; f++)
    offset[f + 1] = offset[f] + count[f];
  int *indices = rf_alloc(last - first, sizeof(int));
  for (int i = first; i < last; i++) {
    int f = c->p[i].flow;
    if (f >= 0)
      indices[offset[f] + cursor[f]++] = i;
  }
  double *sizes = rf_alloc(last - first, sizeof(double)),
         *gaps = rf_alloc(last - first, sizeof(double));
  for (int f = 0; f < c->maxflow; f++)
    if (count[f]) {
      double a[16] = {0}, series[180] = {0};
      int seen[90] = {0}, active = 0, n = count[f], base = offset[f];
      for (int j = 0; j < n; j++) {
        RFPacket *p = c->p + indices[base + j];
        int sec = (int)floor(p->t - start);
        a[p->in] += p->length;
        a[2 + p->in]++;
        series[sec * 2 + p->in] += p->length;
        if (!seen[sec]) {
          seen[sec] = 1;
          active++;
        }
        sizes[j] = p->length;
        if (j)
          gaps[j - 1] = p->t - c->p[indices[base + j - 1]].t;
      }
      a[4] = (c->p[indices[base]].t - start) / seconds;
      a[5] = (c->p[indices[base + n - 1]].t - start) / seconds;
      a[6] = active / (double)seconds;
      qsort(sizes, n, sizeof(double), rf_cmp);
      qsort(gaps, n - 1, sizeof(double), rf_cmp);
      a[7] = rf_quantile(sizes, n, .5);
      a[8] = rf_quantile(sizes, n, .9);
      a[9] = rf_quantile(gaps, n - 1, .5);
      a[10] = rf_quantile(gaps, n - 1, .9);
      a[11] = a[0] / (a[0] + a[1]);
      a[12] = (a[0] + a[1]) / total;
      int proto = c->p[indices[base]].proto;
      a[13] = proto == 6;
      a[14] = proto == 17;
      a[15] = proto != 6 && proto != 17;
      for (int k = 0; k < 16; k++) {
        double v = a[k];
        if (k < 4 || (k >= 7 && k <= 10))
          v = log1p(v);
        out->attr[map[f] * 16 + k] = (float)((v - norm[80 + k]) / norm[96 + k]);
      }
      for (int k = 0; k < seconds * 2; k++)
        out->temporal[map[f] * seconds * 2 + k] =
            (float)((log1p(series[k]) - norm[112 + k % 2]) / norm[114 + k % 2]);
    }
  double *r = out->raw_context;
  r[0] = total;
  r[1] = last - first;
  r[2] = out->n;
  double quality[9] = {0};
  double wire_total = 0;
  for (int i = first; i < last; i++) {
    RFPacket *p = c->p + i;
    for (int j = 0; j < 9; j++)
      if (p->quality & (1u << j))
        quality[j] += p->length;
    if (p->transport_flow >= 0) {
      wire_total += p->wire;
      for (int j = 0; j < 16; j++)
        if (p->legacy & (1u << j))
          out->owners[j] += p->wire;
    }
  }
  for (int j = 0; j < 16; j++)
    out->owners[j] /= wire_total > 0 ? wire_total : 1;
  for (int g = 0; g < 27; g++) {
    double mass = 0, payload = 0, udp = 0, down = 0, series[90] = {0},
           maxbytes = 0;
    int n = 0, nf = 0, maxcount = 0;
    memset(cursor, 0, c->maxflow * sizeof(int));
    double *fm = rf_alloc(c->maxflow, sizeof(double));
    for (int i = first; i < last; i++) {
      RFPacket *p = c->p + i;
      if (!(p->bits & (1u << g)))
        continue;
      mass += p->length;
      n++;
      payload += p->payload;
      if (p->proto == 17)
        udp += p->length;
      if (p->in) {
        down += p->length;
        series[(int)floor(p->t - start)] += p->length;
      }
      if (p->flow >= 0) {
        int f = p->flow;
        if (!cursor[f]++)
          nf++;
        fm[f] += p->length;
        if (cursor[f] > maxcount)
          maxcount = cursor[f];
        if (fm[f] > maxbytes)
          maxbytes = fm[f];
      }
    }
    double peak = 0, var = 0;
    int active = 0, runs = 0;
    for (int j = 0; j < seconds; j++) {
      if (series[j]) {
        active++;
        if (j == 0 || !series[j - 1])
          runs++;
      }
      if (series[j] > peak)
        peak = series[j];
    }
    double mean = active ? down / active : 0;
    for (int j = 0; j < seconds; j++)
      if (series[j])
        var += (series[j] - mean) * (series[j] - mean);
    double values[12] = {total ? mass / total : 0,
                         last > first ? (double)n / (last - first) : 0,
                         out->n ? (double)nf / out->n : 0,
                         mass ? down / mass : 0,
                         mass ? payload / mass : 0,
                         mass ? udp / mass : 0,
                         active / (double)seconds,
                         active ? sqrt(var / active) / mean : 0,
                         down ? peak / down : 0,
                         runs,
                         n ? (double)maxcount / n : 0,
                         mass ? maxbytes / mass : 0};
    memcpy(r + 3 + g * 12, values, sizeof(values));
    free(fm);
  }
  for (int i = 0; i < c->ne; i++) {
    RFEvent *e = c->ev + i;
    if (e->t < min_time || e->t >= start + seconds)
      continue;
    unsigned bits = 0;
    for (int j = 0; j < e->nn; j++)
      bits |= c->namebits[e->names[j]];
    for (int g = 0; g < 22; g++)
      if (bits & (1u << g))
        r[327 + g * 2 + (e->kind != 0)]++;
  }
  int j = 371;
  for (int k = 0; k < 9; k++)
    if (k != 3)
      r[j++] = total ? quality[k] / total : 0;
  r[379] = total ? assigned / total : 0;
  for (int k = 0; k < 380; k++) {
    double v = (log1p(r[k]) - norm[116 + k]) / norm[496 + k];
    out->context[k] = (float)fmax(-10, fmin(10, v));
  }
  free(count);
  free(map);
  free(offset);
  free(cursor);
  free(indices);
  free(sizes);
  free(gaps);
}
static void rf_input_free(RFInput *p) {
  free(p->device);
  free(p->attr);
  free(p->temporal);
}
