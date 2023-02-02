#pragma once

#define XLOG_DEBUG(FORMAT, ...) hidp_log_printf(LogLevel::Debug, FORMAT, ## __VA_ARGS__)
#define XLOG_INFO(FORMAT, ...) hidp_log_printf(LogLevel::Info, FORMAT, ## __VA_ARGS__)
#define XLOG_WARN(FORMAT, ...) hidp_log_printf(LogLevel::Warn, FORMAT, ## __VA_ARGS__)
#define XLOG_ERROR(FORMAT, ...) hidp_log_printf(LogLevel::Error, FORMAT, ## __VA_ARGS__)
#define XLOG_FATAL(FORMAT, ...) hidp_log_printf(LogLevel::Fatal, FORMAT, ## __VA_ARGS__)

enum class LogLevel {
  None,
  Debug,
  Info,
  Warn,
  Error,
  Fatal
};

void hidp_log_printf(LogLevel level, const char *format, ...)
  __attribute__((format (printf, 2, 3)));

void hidp_throw_errno(int err, const char *format, ...)
  __attribute__ ((format (printf, 2, 3)));
