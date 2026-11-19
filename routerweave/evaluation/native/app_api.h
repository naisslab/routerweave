#pragma once
#ifdef __cplusplus
extern "C" {
#endif
void rw_application_load(const char *, const char *,
                         const char **, int);
void rw_application_start(double);
void rw_application_mode(int);
void rw_application_packet(int, const unsigned char *, unsigned, unsigned,
                           double, unsigned);
void rw_application_step(double);
unsigned long rw_application_calls(void);
#ifdef __cplusplus
}
#endif
