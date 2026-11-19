/* Experimental frozen current Screen Time pipeline. No runtime ML dependency.
 */
#define _GNU_SOURCE
#define RF_CLASSES 6
#include "film_inference.c"
#include "router_features.h"
static double started;
static int streams;
static RFCapture *captures;
static Net network;
static Reader weights;
static double normalization[956], identity[876];
static void prepare(RFCapture *c, double end, int seconds, RFInput *x) {
  double start = end - seconds;
  rf_extract_length(c, start, start, seconds, identity, x);
  double h[40] = {0};
  for (int i = 0; i < c->np; i++) {
    RFPacket *p = c->p + i;
    if (p->t < start || p->t >= end)
      continue;
    int o = p->in * 20;
    h[o]++;
    h[o + 1] += p->length;
    h[o + 2] += p->proto == 6;
    h[o + 3] += p->proto == 17;
    h[o + 10 + (p->ttl > 32) + (p->ttl > 64) + (p->ttl > 128)]++;
    if (p->header_valid && p->proto == 6) {
      h[o + 4] += p->payload;
      int flags = p->tcp_flags;
      h[o + 5] += p->payload == 0 && (flags & 16) && !(flags & 7);
      h[o + 6] += (flags & 2) != 0;
      h[o + 7] += (flags & 1) != 0;
      h[o + 8] += (flags & 4) != 0;
      h[o + 9] += (flags & 8) != 0;
      unsigned w = p->tcp_window;
      h[o + 14 + (w > 0) + (w > 1024) + (w > 8192) + (w > 32768) +
        (w > 65534)]++;
    }
  }
  for (int o = 0; o <= 20; o += 20) {
    double valid = 0;
    for (int j = 14; j < 20; j++)
      valid += h[o + j];
    valid = fmax(1, valid);
    double packets = fmax(1, h[o]), volume = fmax(1, h[o + 1]);
    for (int j = 0; j < 20; j++)
      x->header[o + j] =
          j < 2 ? log1p(h[o + j])
                : h[o + j] /
                      (j == 4
                           ? volume
                           : ((j >= 5 && j <= 9) || j >= 14 ? valid : packets));
  }
}
