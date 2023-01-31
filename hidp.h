
#pragma once

#include <sys/select.h>
#include <string>
#include <sys/socket.h>

#define XLOG_DEBUG(FORMAT, ...) hidp_log_printf(XLOG_LEVEL_DEBUG, FORMAT, ## __VA_ARGS__)
#define XLOG_INFO(FORMAT, ...) hidp_log_printf(XLOG_LEVEL_INFO, FORMAT, ## __VA_ARGS__)
#define XLOG_WARN(FORMAT, ...) hidp_log_printf(XLOG_LEVEL_WARN, FORMAT, ## __VA_ARGS__)
#define XLOG_ERROR(FORMAT, ...) hidp_log_printf(XLOG_LEVEL_ERROR, FORMAT, ## __VA_ARGS__)
#define XLOG_FATAL(FORMAT, ...) hidp_log_printf(XLOG_LEVEL_FATAL, FORMAT, ## __VA_ARGS__)

enum xLogLevel
{
  XLOG_LEVEL_NONE  = 0,
  XLOG_LEVEL_DEBUG = 1,
  XLOG_LEVEL_INFO  = 2,
  XLOG_LEVEL_WARN  = 3,
  XLOG_LEVEL_ERROR = 4,
  XLOG_LEVEL_FATAL = 5
};

enum PacketType {
  PacketTypeCreate = 0x01,
  PacketTypeDelete = 0x02,
  PacketTypeReport = 0x03,
  PacketTypeGetReportRequest = 0x04,
  PacketTypeGetReportResponse = 0x05
};

struct HIDCommandPacketHeader
{
  int16_t packet_size;
  int16_t channel_id;
  int16_t packet_type;
  int16_t event_type;
  char    packet_data[0];
};

void hid_command_packet_header_from_network(HIDCommandPacketHeader *header);
void hid_command_packet_header_to_network(HIDCommandPacketHeader *header);

void         hidp_log_printf(xLogLevel level, const char *format, ...);
const char  *hidp_bus_to_string(int bus);
void         hidp_push_fd(fd_set *set, int fd, int *max);
int          hidp_read_until(int fd, void *buff, int count);
std::string  hipd_socketaddr_to_string(sockaddr_storage &ss);
