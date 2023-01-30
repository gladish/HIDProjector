#include "hidp.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
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
  XLOG_INFO(" ---  begin new device --- ");
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
  XLOG_INFO(" --- end new device -- ");
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
