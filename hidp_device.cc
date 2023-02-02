#include "hidp_common.h"
#include "hidp_device.h"

#include <linux/hidraw.h>
#if WITH_UUID
#include <linux/uhid.h>
#else
#include <stdio.h>
#endif
#include <libudev.h>
#include <uuid/uuid.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int16_t NextChannelId = 1000;

InputDevice::InputDevice()
  : m_channel_id(-1)
  , m_fd(-1)
  , m_descriptor_size(0)
  , m_bus_type(0)
  , m_vendor_id(0)
  , m_product_id(0)
  , m_input_report_size(0)
{
  m_name[0] = '\0';

  char temp[256] = {};

  #if WITH_UUID
  uuid_t id;
  uuid_generate_random(id);
  uuid_unparse_lower(id, temp);
  #else
  FILE *uuid_file = fopen("/proc/sys/kernel/random/uuid", "r");
  if (uuid_file) {
    fread(temp, sizeof(temp), 1, uuid_file);
    fclose(uuid_file);
  }
  else {
    // TODO
  }
  #endif

  m_uuid = temp;
}

#ifdef WITH_INPUTDEVICE_MONITOR
InputDeviceMonitor::InputDeviceMonitor()
  : m_fd(-1)
  , m_udev_monitor(nullptr)
  , m_udev(nullptr)
{
  m_udev = udev_new();
  m_udev_monitor = udev_monitor_new_from_netlink(m_udev, "udev");
  udev_monitor_enable_receiving(m_udev_monitor);
  m_fd = udev_monitor_get_fd(m_udev_monitor);
}

InputDeviceMonitor::~InputDeviceMonitor()
{
  if (m_udev)
    udev_unref(m_udev);
}

void
InputDeviceMonitor::ReadNext(InputDeviceAdded on_device_added, InputDeviceRemoved on_device_removed)
{
  udev_device *dev = udev_monitor_receive_device(m_udev_monitor);
  if (!dev) {
    return;
  }

  const char *action = udev_device_get_action(dev);
  if (strcasecmp(action, "add") == 0) {
    const char *device_node = udev_device_get_devnode(dev);
    auto itr = m_device_ids.find(device_node);
    if (itr != std::end(m_device_ids) && on_device_removed) {
      on_device_removed(itr->second);
      m_device_ids.erase(itr);
    }
  }

  if (strcasecmp(action, "remove") == 0) {
    if (on_device_added) {
      std::unique_ptr<InputDevice> new_device = InputDeviceMonitor::FromDevice(dev);
      on_device_added(std::move(new_device));
    }
  }

  udev_device_unref(dev);
}

std::vector<std::unique_ptr<InputDevice>> InputDeviceMonitor::FindAll()
{
  std::vector<std::unique_ptr<InputDevice>> device_monitors;

  udev_enumerate *udev_enum = udev_enumerate_new(m_udev);
  udev_enumerate_add_match_subsystem(udev_enum, "hidraw");
  udev_enumerate_scan_devices(udev_enum);

  udev_list_entry *device_list = udev_enumerate_get_list_entry(udev_enum);
  for (udev_list_entry *iter = device_list; iter; iter = udev_list_entry_get_next(iter)) {
    const char *sysfs_path = udev_list_entry_get_name(iter);

    udev_device *raw_dev = udev_device_new_from_syspath(m_udev, sysfs_path);
    device_monitors.push_back(InputDeviceMonitor::FromDevice(raw_dev));
    udev_device_unref(raw_dev);
  }

  udev_enumerate_unref(udev_enum);

  return device_monitors;
}

std::unique_ptr<InputDevice> InputDeviceMonitor::FromDevice(udev_device *dev)
{
  std::unique_ptr<InputDevice> monitor{ new InputDevice() };

  monitor->m_channel_id = NextChannelId++;

  const char *device_node = udev_device_get_devnode(dev);
  monitor->m_fd = open(device_node, O_RDWR);
  if (monitor->m_fd == -1)
    hidp_throw_errno(errno, "failed to open device %s", device_node);

  hidraw_devinfo info;
  int ret = ioctl(monitor->m_fd, HIDIOCGRAWINFO, &info);
  if (ret == -1)
    hidp_throw_errno(errno, "failed to read device info");

  monitor->m_bus_type = info.bustype;
  monitor->m_vendor_id = info.vendor;
  monitor->m_product_id = info.product;

  ret = ioctl(monitor->m_fd, HIDIOCGRDESCSIZE, &monitor->m_descriptor_size);
  if (ret == -1)
    hidp_throw_errno(errno, "failed to read descriptor size");

  ret = ioctl(monitor->m_fd, HIDIOCGRDESC, &monitor->m_descriptor); 
  if (ret == -1)
    hidp_throw_errno(errno, "failed to read descriptor");

  ret = ioctl(monitor->m_fd, HIDIOCGRAWNAME(255), &monitor->m_name);
  if (ret == -1)
    hidp_throw_errno(errno, "failed to read name");

  return monitor;
}
#endif

void
InputDevice::ReadInputReport()
{
  ssize_t n = read(m_fd, m_input_report, sizeof(m_input_report));
  if (n > 0)
    m_input_report_size = static_cast<int16_t>(n);
  else
    hidp_throw_errno(errno, "failed to read input report");
}

void InputDevice::GetName(char *buff, int count) const
{
  strncpy(buff, m_name, count);
}
