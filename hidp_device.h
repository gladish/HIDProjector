#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>

#include <stdint.h>

template<class T>
struct Buffer
{
  const uint8_t *Data;
  T Length;
};

class ProtocolReader;
class ProtocolWriter;

class InputDevice {
  friend class InputDeviceMonitor;
  friend class ProtocolReader;
public:
  inline int16_t GetChannelId() const;
  inline int GetFD() const;
  inline std::string GetId() const;
  inline int16_t GetBusType() const;
  inline int16_t GetProductId() const;
  inline int16_t GetVendorId() const;
  void ReadInputReport();
  void GetName(char *buff, int count) const;
  inline Buffer<uint16_t> GetHIDReport() const;
  inline Buffer<uint32_t> GetHIDDescriptor() const;
private:
  InputDevice();
  int16_t       m_channel_id;
  int           m_fd;
  char          m_name[256];

  // descriptor
  uint32_t      m_descriptor_size;
  uint8_t       m_descriptor[8192];

  // device info
  int16_t       m_bus_type;
  int16_t       m_vendor_id;
  int16_t       m_product_id;

  std::string   m_uuid;
  uint8_t       m_input_report[256];
  uint16_t      m_input_report_size;
};

#ifdef WITH_INPUTDEVICE_MONITOR
struct udev;
struct udev_device;
struct udev_monitor;

using InputDeviceAdded = std::function<void (std::unique_ptr<InputDevice>)>;
using InputDeviceRemoved = std::function<void (std::string uuid)>;

class InputDeviceMonitor {
public:
  InputDeviceMonitor();
  ~InputDeviceMonitor();
  inline int GetFD() const;
  void ReadNext(InputDeviceAdded on_device_added, InputDeviceRemoved on_device_removed);
public:
  std::vector<std::unique_ptr<InputDevice>> FindAll();
  static std::unique_ptr<InputDevice> FromDevice(udev_device *device);
private:
  using StringMap = std::map<std::string, std::string >;

  int           m_fd;
  udev_monitor *m_udev_monitor;
  udev         *m_udev;
  StringMap     m_device_ids;
};
#endif

#ifdef WITH_INPUTDEVICE_MONITOR
inline int InputDeviceMonitor::GetFD() const
{
  return m_fd;
}
#endif

inline int16_t InputDevice::GetChannelId() const
{
  return m_channel_id;
}

inline int InputDevice::GetFD() const
{
  return m_fd;
}

inline std::string InputDevice::GetId() const
{
  return m_uuid;
}

inline int16_t InputDevice::GetBusType() const
{
  return m_bus_type;
}

inline int16_t InputDevice::GetProductId() const
{
  return m_product_id;
}

inline int16_t InputDevice::GetVendorId() const
{
  return m_vendor_id;
}

inline Buffer<uint32_t> InputDevice::GetHIDDescriptor() const
{
  return Buffer<uint32_t>{ m_descriptor, m_descriptor_size };
}

inline Buffer<uint16_t> InputDevice::GetHIDReport() const
{
  return Buffer<uint16_t>{ m_input_report, m_input_report_size };
}
