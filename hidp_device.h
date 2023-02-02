#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>

#include <stdint.h>

template<class T>
struct BufferReference
{
  const uint8_t *Data;
  T Length;
};

class ProtocolRead;
class ProtocolWriter;

class InputDevice {
  friend class InputDeviceMonitor;
  friend class ProtocolWriter;
public:
  inline int16_t ChannelId() const;
  inline int Descriptor() const;
  inline std::string Id() const;
  inline int16_t GetBusType() const;
  inline int16_t GetProductId() const;
  inline int16_t GetVendorId() const;
  void ReadInputReport();
  void GetName(char *buff, int count) const;
private:
  InputDevice();
  inline BufferReference<int16_t> GetReport() const;
  inline BufferReference<uint32_t> GetDescriptor() const;
private:
  int16_t       m_channel_id;
  int           m_fd;
  char          m_name[256];

  // descriptor
  uint32_t      m_descriptor_size;
  uint8_t       m_descriptor[4096];

  // device info
  uint32_t      m_bus_type;
  int16_t       m_vendor_id;
  int16_t       m_product_id;

  std::string   m_uuid;
  uint8_t       m_input_report[256];
  int16_t       m_input_report_size;
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
  inline int Descriptor() const;
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
inline int InputDeviceMonitor::Descriptor() const
{
  return m_fd;
}
#endif

inline int16_t InputDevice::ChannelId() const
{
  return m_channel_id;
}

inline int InputDevice::Descriptor() const
{
  return m_fd;
}

inline std::string InputDevice::Id() const
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

inline BufferReference<uint32_t> InputDevice::GetDescriptor() const
{
  return BufferReference<uint32_t>{ m_descriptor, m_descriptor_size };
}

inline BufferReference<int16_t> InputDevice::GetReport() const
{
  return BufferReference<int16_t>{ m_input_report, m_input_report_size };
}
