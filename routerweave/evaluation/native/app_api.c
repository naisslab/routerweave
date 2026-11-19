#include "app_api.h"
#include "activity_pipeline.c"
static unsigned long rw_calls;
static double rw_latest[64];
static int rw_log_paced;
void rw_application_load(const char *wp, const char *np,
                         const char **ips, int n) {
  if (n < 1 || n > 64)
    rf_fail("application streams");
  streams = n;
  size_t bytes;
  weights.data = read_file(wp, &bytes);
  weights.size = bytes / 4;
  load_net(&weights, &network);
  if (weights.used != weights.size)
    rf_fail("primary weight layout");
  FILE *f = fopen(np, "rb");
  if (!f || fread(normalization, 8, 956, f) != 956 || fgetc(f) != EOF)
    rf_fail("normalizer layout");
  fclose(f);
  for (int i = 40; i < 80; i++)
    identity[i] = 1;
  for (int i = 96; i < 112; i++)
    identity[i] = 1;
  for (int i = 114; i < 116; i++)
    identity[i] = 1;
  for (int i = 496; i < 876; i++)
    identity[i] = 1;
  captures = rf_alloc(n, sizeof(RFCapture));
  for (int d = 0; d < n; d++) {
    rf_init(captures + d, ips[d]);
    rw_latest[d] = -INFINITY;
  }
}
void rw_application_start(double t) { started = t; }
void rw_application_mode(int value) { rw_log_paced = value; }
void rw_application_packet(int d, const unsigned char *packet, unsigned cap,
                           unsigned wire, double stamp, unsigned link) {
  rf_ingest(captures + d, packet, cap, wire, stamp, link);
  rw_latest[d] = fmax(rw_latest[d], stamp);
}
void rw_application_step(double cutoff) {
  for (int d = 0; d < streams; d++) {
    if (rw_latest[d] >= cutoff)
      rf_fail("future application input");
    RFCapture *c = captures + d;
    double begin = now_seconds();
    rf_associate(c);
    RFInput x;
    prepare(c, cutoff, 30, &x);
    float header[40], p[6];
    current_normalize(normalization, x.device, x.attr, x.temporal, x.n, 30,
                      x.raw_context, x.context, x.header, header);
    double ready = now_seconds();
    rw_calls++;
    current_forward(&network, x.device, x.attr, x.temporal, x.n, x.context,
                    header, 30, 2, p);
    double done = now_seconds();
    int label = 0;
    for (int j = 1; j < 6; j++)
      if (p[j] > p[label])
        label = j;
    printf("{\"type\":\"prediction\",\"stream\":%d,\"cutoff\":%.17g,\"label\":%"
           "d,\"feature_seconds\":%.17g,\"inference_seconds\":%.17g,\"native_"
           "elapsed\":%.17g,\"probabilities\":[",
           d, cutoff, label, ready - begin, done - ready, done - started);
    for (int j = 0; j < 6; j++)
      printf("%s%.9g", j ? "," : "", p[j]);
    printf("]}\n");
    printf("{\"type\":\"execution\",\"stream\":%d,\"cutoff\":%.17g,\"primary_"
           "calls\":1,\"input_lengths\":[30],\"latest_packet\":%.17g}\n",
           d, cutoff, rw_latest[d]);
    rf_input_free(&x);
    rf_prune(c, cutoff - 30);
  }
  if (rw_log_paced)
    fflush(stdout);
}
unsigned long rw_application_calls(void) { return rw_calls; }
