#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#endif
#ifdef _WIN32
#define API __declspec(dllexport)
#else
#define API __attribute__((visibility("default")))
#endif
typedef struct {
  int n;
  const int32_t *left, *right, *feature;
  const double *threshold, *probability;
  const unsigned char *compact;
} Tree;
typedef struct {
  int device, label, n;
  Tree *trees;
} Forest;
typedef struct {
  unsigned char *raw;
  size_t size, at;
  int n;
  Forest *forests;
} Model;
static int take_int(Model *m, int *out) {
  if (m->at + 4 > m->size)
    return 0;
  memcpy(out, m->raw + m->at, 4);
  m->at += 4;
  return 1;
}
static const void *take_array(Model *m, size_t bytes) {
  m->at = (m->at + 7) & ~(size_t)7;
  if (m->at > m->size || bytes > m->size - m->at)
    return NULL;
  const void *p = m->raw + m->at;
  m->at += bytes;
  return p;
}
API void *rf_load_model(const char *path) {
  Model *m = calloc(1, sizeof(*m));
  if (!m)
    return NULL;
#ifdef _WIN32
  FILE *f = fopen(path, "rb");
  if (!f) {
    free(m);
    return NULL;
  }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  rewind(f);
  m->size = n;
  m->raw = malloc(n);
  if (!m->raw || fread(m->raw, 1, n, f) != (size_t)n) {
    fclose(f);
    free(m->raw);
    free(m);
    return NULL;
  }
  fclose(f);
#else
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    free(m);
    return NULL;
  }
  m->size = lseek(fd, 0, SEEK_END);
  char *tail = malloc(strlen(path) + 6);
  if (!tail) {
    close(fd);
    free(m);
    return NULL;
  }
  sprintf(tail, "%s.tail", path);
  int second = open(tail, O_RDONLY);
  free(tail);
  if (second >= 0) {
    size_t first = m->size, extra = lseek(second, 0, SEEK_END);
    if (first % 4096) {
      close(fd);
      close(second);
      free(m);
      return NULL;
    }
    m->size += extra;
    m->raw = mmap(NULL, m->size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m->raw == MAP_FAILED) {
      close(fd);
      close(second);
      free(m);
      return NULL;
    }
    if (mmap(m->raw, first, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 0) ==
            MAP_FAILED ||
        mmap(m->raw + first, extra, PROT_READ, MAP_PRIVATE | MAP_FIXED, second,
             0) == MAP_FAILED) {
      munmap(m->raw, m->size);
      close(fd);
      close(second);
      free(m);
      return NULL;
    }
    close(second);
  } else
    m->raw = mmap(NULL, m->size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (m->raw == MAP_FAILED) {
    free(m);
    return NULL;
  }
#endif
  int magic;
  if (!take_int(m, &magic) || (magic != 0x31534652 && magic != 0x32534652) ||
      !take_int(m, &m->n) || m->n < 1 || m->n > 1000)
    return NULL;
  m->forests = calloc(m->n, sizeof(Forest));
  if (!m->forests)
    return NULL;
  for (int i = 0; i < m->n; i++) {
    Forest *f = m->forests + i;
    if (!take_int(m, &f->device) || !take_int(m, &f->label) ||
        !take_int(m, &f->n) || f->n < 1 || f->n > 10000)
      return NULL;
    f->trees = calloc(f->n, sizeof(Tree));
    if (!f->trees)
      return NULL;
    for (int j = 0; j < f->n; j++) {
      Tree *t = f->trees + j;
      if (!take_int(m, &t->n) || t->n < 1 || t->n > 10000000)
        return NULL;
      if (magic == 0x32534652) {
        t->compact = take_array(m, t->n);
        if (!t->compact)
          return NULL;
      } else {
        t->left = take_array(m, t->n * 4u);
        t->right = take_array(m, t->n * 4u);
        t->feature = take_array(m, t->n * 4u);
        t->threshold = take_array(m, t->n * 8u);
        t->probability = take_array(m, t->n * 8u);
        if (!t->left || !t->right || !t->feature || !t->threshold ||
            !t->probability)
          return NULL;
      }
    }
  }
  if (m->at != m->size)
    return NULL;
  return m;
}
typedef struct {
  Model *m;
  int device, begin, end;
  const float *x;
  int32_t *labels;
  double *probability;
} Work;
static void *evaluate(void *arg) {
  Work *w = arg;
  for (int row = w->begin; row < w->end; row++) {
    double best = 0;
    int label = -1;
    const float *x = w->x + row * 22;
    for (int k = 0; k < w->m->n; k++) {
      Forest *f = w->m->forests + k;
      if (f->device != w->device)
        continue;
      double total = 0;
      for (int j = 0; j < f->n; j++) {
        Tree *t = f->trees + j;
        int node = 0;
        if (t->compact) {
          for (;;) {
            if (node < 0 || node >= t->n)
              return (void *)1;
            unsigned feature = t->compact[node];
            if (feature >= 253) {
              double p = feature == 255 ? 1. : 0.;
              if (feature == 253) {
                if (node + 9 > t->n)
                  return (void *)1;
                memcpy(&p, t->compact + node + 1, 8);
              }
              total += p;
              break;
            }
            if (feature >= 22 || node + 13 > t->n)
              return (void *)1;
            uint32_t right;
            double threshold;
            memcpy(&right, t->compact + node + 1, 4);
            memcpy(&threshold, t->compact + node + 5, 8);
            node = x[feature] <= threshold ? node + 13 : (int)right;
          }
        } else {
          while (t->left[node] >= 0) {
            int feature = t->feature[node];
            if (feature < 0 || feature >= 22)
              return (void *)1;
            node = x[feature] <= t->threshold[node] ? t->left[node]
                                                    : t->right[node];
            if (node < 0 || node >= t->n)
              return (void *)1;
          }
          total += t->probability[node];
        }
      }
      total /= f->n;
      if (total > .5 && total > best) {
        best = total;
        label = f->label;
      }
    }
    w->labels[row] = label;
    w->probability[row] = best;
  }
  return NULL;
}
API int rf_predict(void *model, int device, const float *x, int rows,
                   int32_t *labels, double *probability) {
  if (!model || rows < 0)
    return 1;
  Work a = {(Model *)model, device, 0, rows, x, labels, probability};
#ifndef _WIN32
  if (rows > 1) {
    Work b = a;
    a.end = rows / 2;
    b.begin = a.end;
    pthread_t thread;
    if (pthread_create(&thread, NULL, evaluate, &b))
      return 2;
    void *r = evaluate(&a), *s = NULL;
    pthread_join(thread, &s);
    return r || s ? 3 : 0;
  }
#endif
  return evaluate(&a) ? 3 : 0;
}
API void rf_free_model(void *model) {
  if (!model)
    return;
  Model *m = model;
  for (int i = 0; i < m->n; i++)
    free(m->forests[i].trees);
  free(m->forests);
#ifdef _WIN32
  free(m->raw);
#else
  munmap(m->raw, m->size);
#endif
  free(m);
}
