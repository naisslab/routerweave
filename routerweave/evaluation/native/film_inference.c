#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Serial scheduler selects native5/10/30; workers share this read-only value.
 */
static int current_steps = 30;
#define T_STEPS current_steps
#define CURRENT_MAX_STEPS 90
#define HEADER_W 64
#define DEV_IN 40
#define DEV_W 64
#define CONN_IN 2
#define CONN_W 32
#define ATTR_IN 16
#define ATTR_W 32
#define FUSE_IN (ATTR_W + 2 * CONN_W)
#define FUSE_W 64
#define TRAFFIC_W (2 * DEV_W + FUSE_W + HEADER_W)
#define HIDDEN_W 256
#define SERVICE_W 304
#ifndef RF_CLASSES
#define RF_CLASSES 7
#endif
#if RF_CLASSES != 6 && RF_CLASSES != 7
#error                                                                         \
    "The router probe supports only the registered six- and seven-class models"
#endif
#define CLASSES RF_CLASSES
#define EXPERTS 4
#define CONTEXT_W 380
#define MAX_THREADS 8

static const int DILATION[5] = {1, 2, 4, 8, 16};

typedef struct {
  float *data;
  size_t used;
  size_t size;
} Reader;

typedef struct {
  float *owned[24];
  int owned_count;
  const float *dev_proj_wt, *dev_proj_b;
  const float *dev_blk_wt[5][2], *dev_blk_b[5][2];
  const float *attr_w, *attr_b;
  const float *conn_proj_wt, *conn_proj_b;
  const float *conn_blk_wt[5][2], *conn_blk_b[5][2];
  const float *fuse_w, *fuse_b;
  const float *setproj_w, *setproj_b;
  const float *first_w, *first_b;
  const float *genc_w, *genc_b, *benc_w, *benc_b;
  const float *eenc_w, *eenc_b, *qenc_w, *qenc_b;
  const float *rel_w, *rel_b, *mod_w, *mod_b;
  const float *ex1_w[EXPERTS], *ex1_b[EXPERTS];
  const float *ex2_w[EXPERTS], *ex2_b[EXPERTS];
  const float *gate_w, *gate_b;
  const float *header1_w, *header1_b, *header2_w, *header2_b;
} Net;

/* Per-thread convolution scratch, sized for the widest temporal encoder. */
typedef struct {
  float hidden[CURRENT_MAX_STEPS * DEV_W];
  float stage1[CURRENT_MAX_STEPS * DEV_W];
  float stage2[CURRENT_MAX_STEPS * DEV_W];
} Scratch;

static void die(const char *message) {
  fprintf(stderr, "error: %s\n", message);
  exit(1);
}

static float *take(Reader *reader, size_t count) {
  float *block;
  if (reader->used + count > reader->size)
    die("weight file is smaller than the retained checkpoint layout");
  block = reader->data + reader->used;
  reader->used += count;
  return block;
}

static float *keep(Net *net, float *block) {
  if (net->owned_count >= (int)(sizeof(net->owned) / sizeof(net->owned[0])))
    die("too many owned weight buffers");
  net->owned[net->owned_count++] = block;
  return block;
}

/* Conv weights arrive as [out][in][kernel]; the fast kernel wants
 * [kernel][in][out]. */
static float *transpose_conv(Net *net, const float *w, int out_channels,
                             int in_channels, int kernel) {
  float *result =
      malloc(sizeof(float) * (size_t)out_channels * in_channels * kernel);
  int co, ci, k;
  if (result == NULL)
    die("out of memory");
  for (co = 0; co < out_channels; co++)
    for (ci = 0; ci < in_channels; ci++)
      for (k = 0; k < kernel; k++)
        result[((size_t)k * in_channels + ci) * out_channels + co] =
            w[((size_t)co * in_channels + ci) * kernel + k];
  return keep(net, result);
}

static void load_net(Reader *reader, Net *net) {
  int block, layer, expert;
  net->owned_count = 0;
  net->dev_proj_wt = transpose_conv(net, take(reader, (size_t)DEV_W * DEV_IN),
                                    DEV_W, DEV_IN, 1);
  net->dev_proj_b = take(reader, DEV_W);
  for (block = 0; block < 5; block++)
    for (layer = 0; layer < 2; layer++) {
      net->dev_blk_wt[block][layer] = transpose_conv(
          net, take(reader, (size_t)DEV_W * DEV_W * 3), DEV_W, DEV_W, 3);
      net->dev_blk_b[block][layer] = take(reader, DEV_W);
    }
  net->attr_w = take(reader, (size_t)ATTR_W * ATTR_IN);
  net->attr_b = take(reader, ATTR_W);
  net->conn_proj_wt = transpose_conv(
      net, take(reader, (size_t)CONN_W * CONN_IN), CONN_W, CONN_IN, 1);
  net->conn_proj_b = take(reader, CONN_W);
  for (block = 0; block < 5; block++)
    for (layer = 0; layer < 2; layer++) {
      net->conn_blk_wt[block][layer] = transpose_conv(
          net, take(reader, (size_t)CONN_W * CONN_W * 3), CONN_W, CONN_W, 3);
      net->conn_blk_b[block][layer] = take(reader, CONN_W);
    }
  net->fuse_w = take(reader, (size_t)FUSE_W * FUSE_IN);
  net->fuse_b = take(reader, FUSE_W);
  net->setproj_w = take(reader, (size_t)FUSE_W * (2 * FUSE_W + 1));
  net->setproj_b = take(reader, FUSE_W);
  net->first_w = take(reader, (size_t)HIDDEN_W * TRAFFIC_W);
  net->first_b = take(reader, HIDDEN_W);
  net->genc_w = take(reader, (size_t)16 * 3);
  net->genc_b = take(reader, 16);
  net->benc_w = take(reader, (size_t)HIDDEN_W * 324);
  net->benc_b = take(reader, HIDDEN_W);
  net->eenc_w = take(reader, (size_t)32 * 44);
  net->eenc_b = take(reader, 32);
  net->qenc_w = take(reader, (size_t)16 * 9);
  net->qenc_b = take(reader, 16);
  net->rel_w = take(reader, 16);
  net->rel_b = take(reader, 1);
  net->mod_w = take(reader, (size_t)512 * SERVICE_W);
  net->mod_b = take(reader, 512);
  for (expert = 0; expert < EXPERTS; expert++) {
    net->ex1_w[expert] = take(reader, (size_t)128 * HIDDEN_W);
    net->ex1_b[expert] = take(reader, 128);
    net->ex2_w[expert] = take(reader, (size_t)CLASSES * 128);
    net->ex2_b[expert] = take(reader, CLASSES);
  }
  net->gate_w = take(reader, (size_t)EXPERTS * (HIDDEN_W + SERVICE_W));
  net->gate_b = take(reader, EXPERTS);
  net->header1_w = take(reader, 40 * 64);
  net->header1_b = take(reader, 64);
  net->header2_w = take(reader, 64 * HEADER_W);
  net->header2_b = take(reader, HEADER_W);
}

/* x is [steps][in_channels], y is [steps][out_channels], symmetric zero
   padding. Weights use the transposed [kernel][in][out] layout, so the inner
   loop is a contiguous axpy the compiler can vectorise. */
#if defined(__aarch64__) && defined(RF_NATIVE_NEON)
#include <arm_neon.h>
static void conv_neon_32(const float *weights, const float *bias,
                         const float *x, int steps, int inputs, int kernel,
                         int dilation, float *y) {
  for (int t = 0; t < steps; t++) {
    float32x4_t a0 = vld1q_f32(bias + 0);
    float32x4_t a1 = vld1q_f32(bias + 4);
    float32x4_t a2 = vld1q_f32(bias + 8);
    float32x4_t a3 = vld1q_f32(bias + 12);
    float32x4_t a4 = vld1q_f32(bias + 16);
    float32x4_t a5 = vld1q_f32(bias + 20);
    float32x4_t a6 = vld1q_f32(bias + 24);
    float32x4_t a7 = vld1q_f32(bias + 28);
    for (int k = 0; k < kernel; k++) {
      int time = t + (k - kernel / 2) * dilation;
      if (time < 0 || time >= steps)
        continue;
      for (int ci = 0; ci < inputs; ci++) {
        float v = x[(size_t)time * inputs + ci];
        if (v == 0)
          continue;
        const float *w = weights + ((size_t)k * inputs + ci) * 32;
        a0 = vfmaq_n_f32(a0, vld1q_f32(w + 0), v);
        a1 = vfmaq_n_f32(a1, vld1q_f32(w + 4), v);
        a2 = vfmaq_n_f32(a2, vld1q_f32(w + 8), v);
        a3 = vfmaq_n_f32(a3, vld1q_f32(w + 12), v);
        a4 = vfmaq_n_f32(a4, vld1q_f32(w + 16), v);
        a5 = vfmaq_n_f32(a5, vld1q_f32(w + 20), v);
        a6 = vfmaq_n_f32(a6, vld1q_f32(w + 24), v);
        a7 = vfmaq_n_f32(a7, vld1q_f32(w + 28), v);
      }
    }
    vst1q_f32(y + (size_t)t * 32 + 0, a0);
    vst1q_f32(y + (size_t)t * 32 + 4, a1);
    vst1q_f32(y + (size_t)t * 32 + 8, a2);
    vst1q_f32(y + (size_t)t * 32 + 12, a3);
    vst1q_f32(y + (size_t)t * 32 + 16, a4);
    vst1q_f32(y + (size_t)t * 32 + 20, a5);
    vst1q_f32(y + (size_t)t * 32 + 24, a6);
    vst1q_f32(y + (size_t)t * 32 + 28, a7);
  }
}
static void conv_neon_64(const float *weights, const float *bias,
                         const float *x, int steps, int inputs, int kernel,
                         int dilation, float *y) {
  for (int t = 0; t < steps; t++) {
    float32x4_t a0 = vld1q_f32(bias + 0);
    float32x4_t a1 = vld1q_f32(bias + 4);
    float32x4_t a2 = vld1q_f32(bias + 8);
    float32x4_t a3 = vld1q_f32(bias + 12);
    float32x4_t a4 = vld1q_f32(bias + 16);
    float32x4_t a5 = vld1q_f32(bias + 20);
    float32x4_t a6 = vld1q_f32(bias + 24);
    float32x4_t a7 = vld1q_f32(bias + 28);
    float32x4_t a8 = vld1q_f32(bias + 32);
    float32x4_t a9 = vld1q_f32(bias + 36);
    float32x4_t a10 = vld1q_f32(bias + 40);
    float32x4_t a11 = vld1q_f32(bias + 44);
    float32x4_t a12 = vld1q_f32(bias + 48);
    float32x4_t a13 = vld1q_f32(bias + 52);
    float32x4_t a14 = vld1q_f32(bias + 56);
    float32x4_t a15 = vld1q_f32(bias + 60);
    for (int k = 0; k < kernel; k++) {
      int time = t + (k - kernel / 2) * dilation;
      if (time < 0 || time >= steps)
        continue;
      for (int ci = 0; ci < inputs; ci++) {
        float v = x[(size_t)time * inputs + ci];
        if (v == 0)
          continue;
        const float *w = weights + ((size_t)k * inputs + ci) * 64;
        a0 = vfmaq_n_f32(a0, vld1q_f32(w + 0), v);
        a1 = vfmaq_n_f32(a1, vld1q_f32(w + 4), v);
        a2 = vfmaq_n_f32(a2, vld1q_f32(w + 8), v);
        a3 = vfmaq_n_f32(a3, vld1q_f32(w + 12), v);
        a4 = vfmaq_n_f32(a4, vld1q_f32(w + 16), v);
        a5 = vfmaq_n_f32(a5, vld1q_f32(w + 20), v);
        a6 = vfmaq_n_f32(a6, vld1q_f32(w + 24), v);
        a7 = vfmaq_n_f32(a7, vld1q_f32(w + 28), v);
        a8 = vfmaq_n_f32(a8, vld1q_f32(w + 32), v);
        a9 = vfmaq_n_f32(a9, vld1q_f32(w + 36), v);
        a10 = vfmaq_n_f32(a10, vld1q_f32(w + 40), v);
        a11 = vfmaq_n_f32(a11, vld1q_f32(w + 44), v);
        a12 = vfmaq_n_f32(a12, vld1q_f32(w + 48), v);
        a13 = vfmaq_n_f32(a13, vld1q_f32(w + 52), v);
        a14 = vfmaq_n_f32(a14, vld1q_f32(w + 56), v);
        a15 = vfmaq_n_f32(a15, vld1q_f32(w + 60), v);
      }
    }
    vst1q_f32(y + (size_t)t * 64 + 0, a0);
    vst1q_f32(y + (size_t)t * 64 + 4, a1);
    vst1q_f32(y + (size_t)t * 64 + 8, a2);
    vst1q_f32(y + (size_t)t * 64 + 12, a3);
    vst1q_f32(y + (size_t)t * 64 + 16, a4);
    vst1q_f32(y + (size_t)t * 64 + 20, a5);
    vst1q_f32(y + (size_t)t * 64 + 24, a6);
    vst1q_f32(y + (size_t)t * 64 + 28, a7);
    vst1q_f32(y + (size_t)t * 64 + 32, a8);
    vst1q_f32(y + (size_t)t * 64 + 36, a9);
    vst1q_f32(y + (size_t)t * 64 + 40, a10);
    vst1q_f32(y + (size_t)t * 64 + 44, a11);
    vst1q_f32(y + (size_t)t * 64 + 48, a12);
    vst1q_f32(y + (size_t)t * 64 + 52, a13);
    vst1q_f32(y + (size_t)t * 64 + 56, a14);
    vst1q_f32(y + (size_t)t * 64 + 60, a15);
  }
}
#endif
static void conv1d(const float *weights, const float *bias, const float *x,
                   int steps, int in_channels, int out_channels, int kernel,
                   int dilation, float *y) {
  int t, k, ci, co;
#if defined(__aarch64__) && defined(RF_NATIVE_NEON)
  if (out_channels == 32) {
    conv_neon_32(weights, bias, x, steps, in_channels, kernel, dilation, y);
    return;
  }
  if (out_channels == 64) {
    conv_neon_64(weights, bias, x, steps, in_channels, kernel, dilation, y);
    return;
  }
#endif
  for (t = 0; t < steps; t++) {
    float *row = y + (size_t)t * out_channels;
    for (co = 0; co < out_channels; co++)
      row[co] = bias[co];
  }
  for (t = 0; t < steps; t++) {
    float *row = y + (size_t)t * out_channels;
    for (k = 0; k < kernel; k++) {
      int index = t + (k - kernel / 2) * dilation;
      const float *source;
      if (index < 0 || index >= steps)
        continue;
      source = x + (size_t)index * in_channels;
      for (ci = 0; ci < in_channels; ci++) {
        const float value = source[ci];
        const float *weights_row;
        if (value == 0.0f)
          continue;
        weights_row = weights + ((size_t)k * in_channels + ci) * out_channels;
        for (co = 0; co < out_channels; co++)
          row[co] += value * weights_row[co];
      }
    }
  }
}

static void dense(const float *weights, const float *bias, const float *x,
                  int in_features, int out_features, float *y) {
  int co, ci;
  for (co = 0; co < out_features; co++) {
    const float *row = weights + (size_t)co * in_features;
    float sum = bias[co];
    for (ci = 0; ci < in_features; ci++)
      sum += row[ci] * x[ci];
    y[co] = sum;
  }
}

static void relu(float *x, int count) {
  int i;
  for (i = 0; i < count; i++)
    if (x[i] < 0.0f)
      x[i] = 0.0f;
}

/* Symmetric dilated residual encoder, matching TemporalEncoder in torch. */
static void temporal_encoder(const float *proj_w, const float *proj_b,
                             const float *const blk_w[5][2],
                             const float *const blk_b[5][2], const float *x,
                             int in_channels, int width, Scratch *scratch,
                             float *out) {
  float *hidden = scratch->hidden;
  float *stage1 = scratch->stage1;
  float *stage2 = scratch->stage2;
  int block, layer;
  conv1d(proj_w, proj_b, x, T_STEPS, in_channels, width, 1, 1, hidden);
  for (block = 0; block < 5; block++) {
    for (layer = 0; layer < 2; layer++) {
      float *target = layer == 0 ? stage1 : stage2;
      const float *source = layer == 0 ? hidden : stage1;
      conv1d(blk_w[block][layer], blk_b[block][layer], source, T_STEPS, width,
             width, 3, DILATION[block], target);
      relu(target, T_STEPS * width);
    }
    for (layer = 0; layer < T_STEPS * width; layer++)
      hidden[layer] += stage2[layer];
  }
  memcpy(out, hidden, sizeof(float) * (size_t)T_STEPS * (size_t)width);
}

/* mean and max over time, concatenated: temporal_pool in torch. */
static void temporal_pool(const float *x, int width, float *out) {
  int t, c;
  for (c = 0; c < width; c++)
    out[c] = 0.0f;
  for (t = 0; t < T_STEPS; t++) {
    const float *row = x + (size_t)t * width;
    for (c = 0; c < width; c++)
      out[c] += row[c];
  }
  for (c = 0; c < width; c++)
    out[c] /= (float)T_STEPS;
  for (c = 0; c < width; c++)
    out[width + c] = x[c];
  for (t = 1; t < T_STEPS; t++) {
    const float *row = x + (size_t)t * width;
    for (c = 0; c < width; c++)
      if (row[c] > out[width + c])
        out[width + c] = row[c];
  }
}

static void log_softmax(const float *x, int count, float *y) {
  float maximum = x[0], total = 0.0f;
  int i;
  for (i = 1; i < count; i++)
    if (x[i] > maximum)
      maximum = x[i];
  for (i = 0; i < count; i++)
    total += expf(x[i] - maximum);
  for (i = 0; i < count; i++)
    y[i] = (x[i] - maximum) - logf(total);
}

typedef struct {
  const Net *net;
  const float *attributes;
  const float *temporal;
  int first, count;
  float *mean;
  float *maximum;
} ConnectionJob;

/* Encode a contiguous range of connections into that range's mean/max. */
static void encode_connections(const Net *net, const float *attributes,
                               const float *temporal, int first, int count,
                               Scratch *scratch, float *mean, float *maximum) {
  float attribute_hidden[ATTR_W];
  float fused_input[FUSE_IN];
  float fused[FUSE_W];
  float connection_sequence[T_STEPS * CONN_W];
  int i, feature, connection;
  for (feature = 0; feature < FUSE_W; feature++) {
    mean[feature] = 0.0f;
    maximum[feature] = 0.0f;
  }
  for (connection = 0; connection < count; connection++) {
    i = first + connection;
    dense(net->attr_w, net->attr_b, attributes + (size_t)i * ATTR_IN, ATTR_IN,
          ATTR_W, attribute_hidden);
    relu(attribute_hidden, ATTR_W);
    temporal_encoder(net->conn_proj_wt, net->conn_proj_b, net->conn_blk_wt,
                     net->conn_blk_b, temporal + (size_t)i * T_STEPS * CONN_IN,
                     CONN_IN, CONN_W, scratch, connection_sequence);
    temporal_pool(connection_sequence, CONN_W, fused_input + ATTR_W);
    memcpy(fused_input, attribute_hidden, sizeof(attribute_hidden));
    dense(net->fuse_w, net->fuse_b, fused_input, FUSE_IN, FUSE_W, fused);
    relu(fused, FUSE_W);
    for (feature = 0; feature < FUSE_W; feature++) {
      mean[feature] += fused[feature];
      if (fused[feature] > maximum[feature])
        maximum[feature] = fused[feature];
    }
  }
}

static void *connection_worker(void *raw) {
  ConnectionJob *job = raw;
  Scratch *scratch = malloc(sizeof(Scratch));
  if (scratch == NULL)
    die("out of memory");
  encode_connections(job->net, job->attributes, job->temporal, job->first,
                     job->count, scratch, job->mean, job->maximum);
  free(scratch);
  return NULL;
}

static void forward(const Net *net, const float *device,
                    const float *attributes, const float *temporal,
                    int connections, const float *context, const float *header,
                    int threads, float *probability) {
  Scratch *scratch = malloc(sizeof(Scratch));
  ConnectionJob jobs[MAX_THREADS];
  pthread_t handles[MAX_THREADS];
  float partial_mean[MAX_THREADS][FUSE_W], partial_max[MAX_THREADS][FUSE_W];
  float device_sequence[T_STEPS * DEV_W];
  float device_feature[2 * DEV_W];
  float connection_mean[FUSE_W], connection_max[FUSE_W],
      connection_input[2 * FUSE_W + 1];
  float connection_feature[FUSE_W];
  float traffic[TRAFFIC_W];
  float first[HIDDEN_W];
  float service_global[16], service_behavior[HIDDEN_W], service_event[32],
      service_quality[16];
  float service[SERVICE_W], modulation[512];
  float hidden[HIDDEN_W], gate_input[HIDDEN_W + SERVICE_W];
  float routing[EXPERTS], expert_hidden[128], expert_logits[CLASSES];
  float expert_log_probability[EXPERTS][CLASSES];
  float reliability, gamma, beta;
  int i, c, expert, feature, used, launch;

  if (scratch == NULL)
    die("out of memory");
  if (threads < 1)
    threads = 1;
  if (threads > MAX_THREADS)
    threads = MAX_THREADS;
  temporal_encoder(net->dev_proj_wt, net->dev_proj_b, net->dev_blk_wt,
                   net->dev_blk_b, device, DEV_IN, DEV_W, scratch,
                   device_sequence);
  temporal_pool(device_sequence, DEV_W, device_feature);

  used = 0;
  if (threads == 1 || connections < 2) {
    encode_connections(net, attributes, temporal, 0, connections, scratch,
                       partial_mean[0], partial_max[0]);
    used = 1;
  } else {
    const int active = threads < connections ? threads : connections;
    int base = connections / active, extra = connections % active, offset = 0;
    for (launch = 0; launch < active; launch++) {
      jobs[launch].net = net;
      jobs[launch].attributes = attributes;
      jobs[launch].temporal = temporal;
      jobs[launch].first = offset;
      jobs[launch].count = base + (launch < extra ? 1 : 0);
      jobs[launch].mean = partial_mean[launch];
      jobs[launch].maximum = partial_max[launch];
      offset += jobs[launch].count;
      if (pthread_create(&handles[launch], NULL, connection_worker,
                         &jobs[launch]) != 0)
        die("cannot start worker thread");
    }
    for (launch = 0; launch < active; launch++)
      pthread_join(handles[launch], NULL);
    used = active;
  }
  for (feature = 0; feature < FUSE_W; feature++) {
    float sum = 0.0f, maximum = partial_max[0][feature];
    for (i = 0; i < used; i++) {
      sum += partial_mean[i][feature];
      if (partial_max[i][feature] > maximum)
        maximum = partial_max[i][feature];
    }
    connection_mean[feature] =
        connections > 0 ? sum / (float)connections : 0.0f;
    connection_max[feature] = maximum;
  }
  memcpy(connection_input, connection_mean, sizeof(connection_mean));
  memcpy(connection_input + FUSE_W, connection_max, sizeof(connection_max));
  connection_input[2 * FUSE_W] = log1pf((float)connections);
  if (connections == 0) {
    /* torch returns an explicit zero representation for empty sets */
    for (feature = 0; feature < FUSE_W; feature++)
      connection_feature[feature] = 0.0f;
  } else {
    dense(net->setproj_w, net->setproj_b, connection_input, 2 * FUSE_W + 1,
          FUSE_W, connection_feature);
  }

  memcpy(traffic, device_feature, sizeof(device_feature));
  memcpy(traffic + 2 * DEV_W, connection_feature, sizeof(connection_feature));
  float header_hidden[64];
  dense(net->header1_w, net->header1_b, header, 40, 64, header_hidden);
  relu(header_hidden, 64);
  dense(net->header2_w, net->header2_b, header_hidden, 64, HEADER_W,
        traffic + 192);
  relu(traffic + 192, HEADER_W);

  dense(net->first_w, net->first_b, traffic, TRAFFIC_W, HIDDEN_W, first);

  dense(net->genc_w, net->genc_b, context, 3, 16, service_global);
  relu(service_global, 16);
  dense(net->benc_w, net->benc_b, context + 3, 324, HIDDEN_W, service_behavior);
  relu(service_behavior, HIDDEN_W);
  dense(net->eenc_w, net->eenc_b, context + 327, 44, 32, service_event);
  relu(service_event, 32);
  dense(net->qenc_w, net->qenc_b, context + 371, 9, 16, service_quality);
  relu(service_quality, 16);
  memcpy(service, service_global, sizeof(service_global));
  memcpy(service + 16, service_behavior, sizeof(service_behavior));
  memcpy(service + 16 + HIDDEN_W, service_event, sizeof(service_event));

  {
    float raw = net->rel_b[0];
    for (i = 0; i < 16; i++)
      raw += net->rel_w[i] * service_quality[i];
    reliability = 1.0f / (1.0f + expf(-raw));
  }
  dense(net->mod_w, net->mod_b, service, SERVICE_W, 512, modulation);
  for (i = 0; i < HIDDEN_W; i++) {
    gamma = modulation[i] * reliability;
    beta = modulation[HIDDEN_W + i] * reliability;
    hidden[i] = first[i] * (1.0f + tanhf(gamma)) + beta;
    hidden[i] = hidden[i] > 0.0f ? hidden[i] : 0.0f;
  }

  memcpy(gate_input, hidden, sizeof(hidden));
  for (i = 0; i < SERVICE_W; i++)
    gate_input[HIDDEN_W + i] = service[i] * reliability;
  {
    float gate_logits[EXPERTS];
    dense(net->gate_w, net->gate_b, gate_input, HIDDEN_W + SERVICE_W, EXPERTS,
          gate_logits);
    log_softmax(gate_logits, EXPERTS, routing);
  }
  for (expert = 0; expert < EXPERTS; expert++) {
    dense(net->ex1_w[expert], net->ex1_b[expert], hidden, HIDDEN_W, 128,
          expert_hidden);
    relu(expert_hidden, 128);
    dense(net->ex2_w[expert], net->ex2_b[expert], expert_hidden, 128, CLASSES,
          expert_logits);
    log_softmax(expert_logits, CLASSES, expert_log_probability[expert]);
  }

  for (c = 0; c < CLASSES; c++) {
    float maximum = expert_log_probability[0][c] + routing[0];
    float total = 0.0f;
    for (expert = 1; expert < EXPERTS; expert++) {
      const float value = expert_log_probability[expert][c] + routing[expert];
      if (value > maximum)
        maximum = value;
    }
    for (expert = 0; expert < EXPERTS; expert++)
      total +=
          expf((expert_log_probability[expert][c] + routing[expert]) - maximum);
    probability[c] = expf(maximum + logf(total));
  }
  free(scratch);
}

static float *read_file(const char *path, size_t *bytes) {
  FILE *handle = fopen(path, "rb");
  float *buffer;
  long size;
  if (handle == NULL)
    die("cannot open input file");
  if (fseek(handle, 0, SEEK_END) != 0)
    die("cannot seek input file");
  size = ftell(handle);
  if (size <= 0)
    die("input file is empty");
  rewind(handle);
  buffer = malloc((size_t)size);
  if (buffer == NULL)
    die("out of memory");
  if (fread(buffer, 1, (size_t)size, handle) != (size_t)size)
    die("short read");
  fclose(handle);
  *bytes = (size_t)size;
  return buffer;
}

static double now_seconds(void) {
  struct timespec value;
  clock_gettime(CLOCK_MONOTONIC, &value);
  return (double)value.tv_sec + (double)value.tv_nsec * 1e-9;
}

/* Traffic arrays are the pretransformed (log1p) extractor outputs. Context is
 * unlogged raw380 as RFInput.raw_context. Header already has log-count
 * channels. The context/header clipping matches randomized_screen_time.tensors
 * exactly. This mutates the arrays once; never normalize an input twice. */
static void current_normalize(const double norm[956], float *device,
                              float *attr, float *temporal, int n, int seconds,
                              const double raw_context[380], float context[380],
                              const float raw_header[40], float header[40]) {
  for (int i = 0; i < seconds * 40; i++)
    device[i] = (device[i] - norm[i % 40]) / norm[40 + i % 40];
  for (int i = 0; i < n * 16; i++)
    attr[i] = (attr[i] - norm[80 + i % 16]) / norm[96 + i % 16];
  for (int i = 0; i < n * seconds * 2; i++)
    temporal[i] = (temporal[i] - norm[112 + i % 2]) / norm[114 + i % 2];
  for (int i = 0; i < 380; i++)
    context[i] = fmax(-10., fmin(10., (log1p(raw_context[i]) - norm[116 + i]) /
                                          norm[496 + i]));
  for (int i = 0; i < 40; i++)
    header[i] =
        fmax(-10., fmin(10., (raw_header[i] - norm[876 + i]) / norm[916 + i]));
}

/* One serial caller; convolution workers may run concurrently inside a call.
 * All arrays are normalized float32, time-major, with no padding or top-K cap.
 */
static void current_forward(const Net *net, const float *device,
                            const float *attr, const float *temporal, int n,
                            const float context[380], const float header[40],
                            int seconds, int threads, float probability[6]) {
  if (seconds != 5 && seconds != 10 && seconds != 30 && seconds != 90)
    die("unsupported current FiLM observation length");
  if (n < 0)
    die("negative connection count");
  current_steps = seconds;
  forward(net, device, attr, temporal, n, context, header, threads,
          probability);
}
