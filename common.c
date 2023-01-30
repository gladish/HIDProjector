#include "hidp.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

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

void hidp_udev_device_dump(struct udev_device *dev)
{
  if (!dev)
    return;
  XLOG_INFO("devpath     : %s", udev_device_get_devpath(dev));
  XLOG_INFO("subsystem   : %s", udev_device_get_subsystem(dev));
  XLOG_INFO("devtype     : %s", udev_device_get_devtype(dev));
  XLOG_INFO("sysname     : %s", udev_device_get_sysname(dev));
  XLOG_INFO("devnode     : %s", udev_device_get_devnode(dev));

  #if 0
  unsigned bus_type;
  unsigned short dev_vid;
	unsigned short dev_pid;
	char *serial_number_utf8 = NULL;
	char *product_name_utf8 = NULL;

  parse_uevent_info(
    udev_device_get_sysattr_value(dev, "uevent"),
    &bus_type,
    &dev_vid,
    &dev_pid,
    &serial_number_utf8,
    &product_name_utf8);

  XLOG_INFO("bus type    : %s", udev_bustype_to_string(bus_type));
  XLOG_INFO("vid         : %d", dev_vid);
  XLOG_INFO("pid         : %d", dev_pid);
  XLOG_INFO("serial      : %s", serial_number_utf8);
  XLOG_INFO("product     : %s", product_name_utf8);
  #endif
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
  pkt->device_id = le16toh(pkt->device_id);
  pkt->packet_type = le16toh(pkt->packet_type);
  pkt->event_type = le16toh(pkt->event_type);
}

void hid_command_packet_header_to_network(HIDCommandPacketHeader *pkt)
{
  pkt->packet_size = htole16(pkt->packet_size);
  pkt->device_id = htole16(pkt->device_id);
  pkt->packet_type = htole16(pkt->packet_type);
  pkt->event_type = htole16(pkt->event_type);
}


int hidp_read_until(int fd, void *buff, int count)
{
  ssize_t bytes_read = 0;
  ssize_t bytes_to_read = count;
  while (bytes_read < bytes_to_read) {
    ssize_t n = recv(fd, buff + bytes_read, (bytes_to_read - bytes_read), MSG_NOSIGNAL);
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
