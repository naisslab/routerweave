/* Saved float32 GRU/GELU equations. No fitting, pruning or changed parameters.
 */
#include <math.h>
#include <stdlib.h>
#ifndef _WIN32
#include <pthread.h>
#endif
#ifdef _WIN32
#define API __declspec(dllexport)
#else
#define API __attribute__((visibility("default")))
#endif

API void rw_gelu(const float *x, int n, float *out) {
  const float root2 = 1.4142135623730951f;
  for (int i = 0; i < n; i++) {
    float z = x[i] / root2, e = (float)erf((double)z);
    out[i] = (0.5f * x[i]) * (1.0f + e);
  }
}

static float logistic(float v) {
  if (v > 80.f)
    v = 80.f;
  if (v < -80.f)
    v = -80.f;
  return 1.f / (1.f + expf(-v));
}

typedef struct {
  const float *inputs, *weight, *bias;
  float *out, *state, *gates;
  int n, h, reverse;
} Direction;

static void *direction(void *ptr) {
  Direction *a = (Direction *)ptr;
  int h = a->h;
  for (int step = 0; step < a->n; step++) {
    int t = a->reverse ? a->n - 1 - step : step;
    const float *input = a->inputs + (size_t)t * 3 * h;
    for (int j = 0; j < 3 * h; j++) {
      const float *w = a->weight + (size_t)j * h;
      float sum = 0.f;
      for (int k = 0; k < h; k++)
        sum += w[k] * a->state[k];
      a->gates[j] = sum + a->bias[j];
    }
    for (int k = 0; k < h; k++) {
      float reset = logistic(input[k] + a->gates[k]);
      float update = logistic(input[h + k] + a->gates[h + k]);
      float candidate = tanhf(input[2 * h + k] + reset * a->gates[2 * h + k]);
      a->state[k] = (1.f - update) * candidate + update * a->state[k];
      a->out[(size_t)t * 2 * h + a->reverse * h + k] = a->state[k];
    }
  }
  return NULL;
}

API int rw_bigru(const float *forward_input, const float *reverse_input,
                 const float *forward_weight, const float *reverse_weight,
                 const float *forward_bias, const float *reverse_bias, int n,
                 int h, float *out) {
  if (n < 0 || h < 1 || h > 1024)
    return 1;
  if (!n)
    return 0;
  float *memory = calloc((size_t)8 * h, sizeof(float));
  if (!memory)
    return 2;
  Direction forward = {forward_input,
                       forward_weight,
                       forward_bias,
                       out,
                       memory,
                       memory + 2 * h,
                       n,
                       h,
                       0};
  Direction reverse = {reverse_input,
                       reverse_weight,
                       reverse_bias,
                       out,
                       memory + h,
                       memory + 5 * h,
                       n,
                       h,
                       1};
#ifndef _WIN32
  pthread_t thread;
  if (pthread_create(&thread, NULL, direction, &reverse)) {
    free(memory);
    return 3;
  }
  direction(&forward);
  pthread_join(thread, NULL);
#else
  direction(&forward);
  direction(&reverse);
#endif
  free(memory);
  return 0;
}
