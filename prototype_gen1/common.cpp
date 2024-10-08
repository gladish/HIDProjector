#include "hidp.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <linux/input.h>

void hidp_log_printf(xLogLevel level, const char *format, ...)
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
  printf("[%5s] %ld.%04ld : ", level_strings[level], tv.tv_sec, (tv.tv_usec / 1000));

  va_list ptr;
  va_start(ptr, format);
  vprintf(format, ptr);
  va_end(ptr);

  printf("\n");

  if (level == XLOG_LEVEL_FATAL) {
    printf("Fatal error, exiting\n");
    fflush(stdout);
    exit(1);
  }
}

const char *hidp_bus_to_string(int bus)
{
	switch (bus) {
	case BUS_USB:
		return "USB";
		break;
	case BUS_HIL:
		return "HIL";
		break;
	case BUS_BLUETOOTH:
		return "Bluetooth";
		break;
	case BUS_VIRTUAL:
		return "Virtual";
		break;
	default:
		return "Other";
		break;
	}
}

const char *udev_bustype_to_string(unsigned bus_type)
{
  const char *s = "unknown";
  switch (bus_type) {
    case BUS_BLUETOOTH:
      s = "bluetooth"; 
      break;
    case BUS_I2C:
      s = "i2c"; 
      break;
    case BUS_USB:
      s = "usb"; 
      break;
    default:
      return "unknown";
  }
  return s;
}

void hid_command_packet_header_from_network(HIDCommandPacketHeader *pkt)
{
  pkt->packet_size = le16toh(pkt->packet_size);
  pkt->channel_id = le16toh(pkt->channel_id);
  pkt->packet_type = le16toh(pkt->packet_type);
  pkt->event_type = le16toh(pkt->event_type);
}

void hid_command_packet_header_to_network(HIDCommandPacketHeader *pkt)
{
  pkt->packet_size = htole16(pkt->packet_size);
  pkt->channel_id = htole16(pkt->channel_id);
  pkt->packet_type = htole16(pkt->packet_type);
  pkt->event_type = htole16(pkt->event_type);
}

int hidp_read_until(int fd, void *buff, int count)
{
  ssize_t bytes_read = 0;
  ssize_t bytes_to_read = count;
  while (bytes_read < bytes_to_read) {
    uint8_t *p = static_cast<uint8_t *>(buff);
    ssize_t n = recv(fd, p + bytes_read, (bytes_to_read - bytes_read), MSG_NOSIGNAL);
    if (n == 0)
      return -ENOTCONN;
    if (n == -1) {
      int err = errno;
      XLOG_WARN("recv:%s", strerror(errno));
      return -err;
    }
    bytes_read += n;
  }
  return bytes_read;
}

std::string  hipd_socketaddr_to_string(sockaddr_storage &ss)
{
  char buff[64];
  memset(buff, 0, sizeof(buff));

  if (ss.ss_family == AF_INET)
  {
    struct sockaddr_in* v4 = (struct sockaddr_in *) &ss;
    void* addr = &v4->sin_addr;
    int family = AF_INET;

    //if (port)
    //  *port = ntohs(v4->sin_port);
    family = AF_INET;

    if (addr)
      inet_ntop(family, addr, buff, sizeof(buff));
  }

  return std::string(buff);
}

void hidp_push_fd(fd_set *set, int fd, int *max)
{
  FD_SET(fd, set);
  if (fd > *max)
    *max = fd;
  // XLOG_INFO("fd_set(%p, %d) - max:%d", set, fd, *max);
}
