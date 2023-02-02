
#include <linux/hidraw.h>
#include <linux/version.h>
#include <linux/input.h>
#include <libudev.h>
#include <linux/uhid.h>

#include "hidp.h"
#include <vector>

static void find_devices();
static void dump_device(struct udev_device *dev, const char *banner);

int main(int argc, char *argv[])
{
  find_devices();
  return 0;
}

void find_devices()
{
  struct udev *udev = udev_new();
  struct udev_enumerate *udev_enum = udev_enumerate_new(udev);
  udev_enumerate_add_match_subsystem(udev_enum, "hidraw");
  udev_enumerate_scan_devices(udev_enum);

  struct udev_list_entry *device_list = udev_enumerate_get_list_entry(udev_enum);
  for (struct udev_list_entry *iter = device_list; iter; iter = udev_list_entry_get_next(iter)) {
    const char *sysfs_path = udev_list_entry_get_name(iter);

    struct udev_device *raw_dev = udev_device_new_from_syspath(udev, sysfs_path);
    dump_device(raw_dev, "raw device");
    udev_device_unref(raw_dev);
  }

  udev_enumerate_unref(udev_enum);
  udev_unref(udev);
}

void dump_device(struct udev_device *dev, const char *banner)
{
  printf(" --- BEGIN %s ---\n", banner);
  if (dev) {
    printf("syspath     : %s\n", udev_device_get_syspath(dev));
    printf("sysname     : %s\n", udev_device_get_sysname(dev));
    printf("sysnum      : %s\n", udev_device_get_sysnum(dev));
    printf("devpath     : %s\n", udev_device_get_devpath(dev));
    printf("devnode     : %s\n", udev_device_get_devnode(dev));
    printf("devnum      : %lu\n", udev_device_get_devnum(dev));
    printf("devtype     : %s\n", udev_device_get_devtype(dev));
    printf("subsystem   : %s\n", udev_device_get_subsystem(dev));
    printf("driver      : %s\n", udev_device_get_driver(dev));
  }
  printf(" --- END   %s ---\n", banner);
}
