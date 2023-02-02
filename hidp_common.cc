#include "hidp_common.h" 

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <sstream>
#include <errno.h>
#include <string.h>
#include <sys/time.h>

void hidp_log_printf(LogLevel level, const char *format, ...)
{
  const char *level_strings[] = {
    "none",
    "debug",
    "info",
    "warn",
    "error",
    "fatal"
  };

  struct timeval tv;
  gettimeofday(&tv, NULL);
  printf("[%5s] %ld.%04ld : ", level_strings[static_cast<int>(level)], tv.tv_sec, (tv.tv_usec / 1000));

  va_list ptr;
  va_start(ptr, format);
  vprintf(format, ptr);
  va_end(ptr);

  printf("\n");

  if (level == LogLevel::Fatal) {
    printf("Fatal error, exiting\n");
    fflush(stdout);
    exit(1);
  }
}

void hidp_throw_errno(int err, const char *format, ...)
{
  va_list args;
  va_start(args, format);

  char buff[256];
  vsnprintf(buff, sizeof(buff), format, args);
  va_end(args);

  std::stringstream message;
  message << buff;
  message << ". ";
  message << strerror(err);
  throw std::runtime_error(message.str());
}
