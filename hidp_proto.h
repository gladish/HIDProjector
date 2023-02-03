#pragma once

#include <functional>
#include <map>
#include <vector>

#include "hidp_device.h"
#include "hidp_net.h"

enum class InputDeviceAction {
  Added,
  Removed
};

enum class PacketType : int16_t {
  Create       = 0x01,
  Delete       = 0x02,
  InputReport  = 0x03,
  GetReportReq = 0x04,
  GetReportRes = 0x05
};

struct Header {
  int16_t PacketSize;
  int16_t ChannelId;
  int16_t PacketType;
} __attribute__((__packed__));

void HeaderToNetwork(Header &header);
void HeaderFromNetwork(Header &header);

class ProtocolReader;
class ProtocolWriter;

class ProtocolWriter {
public:
  ProtocolWriter(Socket &socket)
    : m_socket(socket) { }
  void SendCreate(const std::unique_ptr<InputDevice> &dev);
  void SendDelete(const std::unique_ptr<InputDevice> &dev);
  void SendInputReport(const std::unique_ptr<InputDevice> &dev);
  void SendGetReportRequest(const std::unique_ptr<InputDevice> &dev);
private:
  void Send(iovec *v, int n);
private:
  Socket        &m_socket;
};

class ProtocolReader {
public:
  ProtocolReader(Socket &socket)
    : m_socket(socket) { }
  void ProcessIncomingClientMessage(std::vector< std::unique_ptr<InputDevice> > &local_devices);
  void ProcessIncomingServerMessage(std::vector< std::unique_ptr<InputDevice> > &local_devices);
private:
  Header ReadHeader();
  void ProcessCreate(Header const &header, std::vector< std::unique_ptr<InputDevice> > &local_devices);
  void ProcessGetReportResponse(Header const &header, std::unique_ptr<InputDevice> &dev);
  void ProcessDelete(Header const &header, std::vector<std::unique_ptr<InputDevice>> &dev);
  void ProcessInputReport(Header const &header, std::unique_ptr<InputDevice> &dev);
private:
  Socket        &m_socket;
  char           m_read_buffer[8192];
};
