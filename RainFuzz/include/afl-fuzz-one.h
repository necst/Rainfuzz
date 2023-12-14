#ifndef _AFL_FUZZ_ONE_H
#define _AFL_FUZZ_ONE_H

#include "config.h"

// RainFuzz variables
// Semaphore  variables for RainFuzz
static sem_t *out_sem;
static sem_t *in_sem;
// Shared memory variables for RainFuzz
char *in_buf_shmem;
char *out_buf_shmem;
// Connection variables
bool connected;
// Logs functions and variables
#ifdef RAIN_LOGS
  FILE *log_file;
  #define INIT_LOG_FILE() { \
    if(log_file == NULL) { \
      char* log_file_dir = alloc_printf("%s/cmutator.log", afl->out_dir); \
      log_file = fopen(log_file_dir, "a"); \
      setvbuf(log_file, NULL, _IONBF, 0); \
    } \
  }
  #define LOG_TIME(fs) { \
    struct timeval current_time; \
    gettimeofday(&current_time, NULL); \
    fprintf(log_file, fs, (current_time.tv_sec * 1000000) + current_time.tv_usec); \
  }
  #define LOG_FS_MESSAGE(fs, arg) { \
    fprintf(log_file, fs, arg); \
  }
  #define LOG_MESSAGE(fs) { \
    fprintf(log_file, fs); \
  }
  #define LOG_SEED(message, buf, len) { \
    fprintf(log_file, message); \
    if(len > 0) { \
      for(u32 i = 0; i < len-1; i++) { \
        fprintf(log_file, "%02X,", buf[i]); \
      } \
      fprintf(log_file, "%02X\n", buf[len - 1]); \
    } \
  }
#else
  #define INIT_LOG_FILE()
  #define LOG_TIME(fs)
  #define LOG_FS_MESSAGE(fs, arg)
  #define LOG_MESSAGE(fs)
  #define LOG_SEED(message, buf, len)
#endif

#endif