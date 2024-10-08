
#include "hidp_common.h"
#include "hidp_proto.h"

#include <memory>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <linux/uhid.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <linux/hidraw.h>

namespace {
  void DumpSendCreate(Header const &header, uhid_create2_req const &req)
  {
    XLOG_INFO("SendCreate");
    XLOG_INFO("h.PacketSize  :%d", header.PacketSize);
    XLOG_INFO("h.ChannelId   :%d", header.ChannelId);
    XLOG_INFO("h.PacketType  :%d", header.PacketType);
    XLOG_INFO("req.name      :%s", req.name);
    XLOG_INFO("req.rd_size   :%d", req.rd_size);
    XLOG_INFO("req.bus       :%d", req.bus);
    XLOG_INFO("req.vendor    :%04x", req.vendor);
    XLOG_INFO("req.product   :%04x", req.product);
    XLOG_INFO("req.version   :%d", req.version);
    XLOG_INFO("req.country   :%d", req.country);
  }
}

void
ProtocolWriter::SendCreate(const std::unique_ptr<InputDevice> &dev)
{
  if (!m_socket.IsConnected())
    return;

  Header header;
  header.PacketSize = sizeof(uhid_create2_req);
  header.ChannelId = dev->GetChannelId();
  header.PacketType = static_cast<int16_t>(PacketType::Create);
  HeaderToNetwork(header);

  uhid_create2_req req = {};
  req.bus = htole32(dev->GetBusType());
  req.vendor = htole32(dev->GetVendorId());
  req.product = htole32(dev->GetProductId());
  const std::string id = dev->GetId();
  memcpy(req.uniq, id.c_str(), id.size());

  std::string name = dev->GetName();
  memcpy(req.name, name.c_str(), sizeof(req.name));

  Buffer<uint32_t> descriptor = dev->GetHIDDescriptor();
  req.rd_size = htole32(descriptor.Length);
  memcpy(req.rd_data, descriptor.Data, descriptor.Length);

  #if 0
  for (int i = 1; i <= req.rd_size; ++i) {
    printf("0x%02x ", req.rd_data[i -1]);
    if (i % 16 == 0)
      printf("\n");
  }
  printf("\n");
  #endif

  DumpSendCreate(header, req);

  iovec iov[2];
  iov[0].iov_base = &header;
  iov[0].iov_len = sizeof(header);
  iov[1].iov_base = &req;
  iov[1].iov_len = sizeof(uhid_create2_req);

  Send(iov, 2);
}

void
ProtocolWriter::SendDelete(const std::unique_ptr<InputDevice> &dev)
{
  if (!m_socket.IsConnected())
    return;

  Header header;
  header.PacketSize = 0;
  header.ChannelId = dev->GetChannelId();
  header.PacketType = static_cast<int16_t>(PacketType::Delete);
  HeaderToNetwork(header);

  iovec iov[1];
  iov[0].iov_base = &header;
  iov[0].iov_len = sizeof(header);

  Send(iov, 1);
}

void
ProtocolWriter::SendInputReport(const std::unique_ptr<InputDevice> &dev)
{
  if (!m_socket.IsConnected())
    return;

  Buffer<uint16_t> report = dev->GetHIDReport();

  Header header;
  header.PacketSize = sizeof(report.Length) + report.Length;
  header.ChannelId = dev->GetChannelId();
  header.PacketType = static_cast<int16_t>(PacketType::InputReport);
  HeaderToNetwork(header);

  // uhid_input2_req req;
  // req.size = htole16(report.Length);
  // memcpy(req.data, report.Data, report.Length);
  int16_t length = htole16(report.Length);

  iovec iov[3];
  iov[0].iov_base = &header;
  iov[0].iov_len = sizeof(header);
  iov[1].iov_base = &length;
  iov[1].iov_len = sizeof(length);
  iov[2].iov_base = (void *) (report.Data);
  iov[2].iov_len = length;

  Send(iov, 3);
}

void
ProtocolWriter::Send(iovec *v, int n)
{
  ssize_t bytes_written = writev(m_socket.GetFD(), v, n);
  if (bytes_written < 0) {
    m_socket.Close();
    hidp_throw_errno(errno, "writev failed");
  }
}

void HeaderToNetwork(Header &header)
{
  header.PacketSize = htole16(header.PacketSize);
  header.ChannelId = htole16(header.ChannelId);
  header.PacketType = htole16(header.PacketType);
}

void HeaderFromNetwork(Header &header)
{
  header.PacketSize = le16toh(header.PacketSize);
  header.ChannelId = le16toh(header.ChannelId);
  header.PacketType = le16toh(header.PacketType);
}

void
ProtocolReader::ProcessIncomingClientMessage(std::vector<std::unique_ptr<InputDevice>> &local_devices)
{
  try {
    const Header header = ReadHeader();
    if (header.PacketType == static_cast<int16_t>(PacketType::GetReportReq)) {
      auto itr = std::find_if(std::begin(local_devices), std::end(local_devices),
        [&header](std::unique_ptr<InputDevice> const &dev) {
          return dev->GetChannelId() == header.ChannelId;
        });

      if (itr == std::end(local_devices)) {
        XLOG_WARN("got request for channel %d, but there's no local device.",
          header.ChannelId);
        return;
      }

      // TODO: this code probably belongs in InputDevice
      uhid_get_report_req req;
      m_socket.Read(&req, header.PacketSize);
      req.id = le32toh(req.id);

      #if 0
      XLOG_INFO("uhid_get_report.id:%d", req.id);
      XLOG_INFO("uhid_get_report_req.rnum:%d", req.rnum);
      #endif

      char buff[256];
      buff[0] = req.rnum;

      int ret = ioctl((*itr)->GetFD(), HIDIOCGFEATURE(256), buff);
      if (ret < 0) {
        int err = errno;
        XLOG_ERROR("failed to request feature from device. %s", strerror(err));
        return;
      }

      // TODO: this code belongs in ProtocolWriter
      uhid_get_report_reply_req res;
      res.id = htole32(req.id);
      res.err = htole16(0);
      res.size = htole16(ret);
      memcpy(res.data, buff, ret);

      Header header;
      header.PacketSize = sizeof(uhid_get_report_reply_req);
      header.ChannelId = (*itr)->GetChannelId();
      header.PacketType = static_cast<int16_t>(PacketType::GetReportRes);
      HeaderToNetwork(header);

      iovec iov[2];
      iov[0].iov_base = &header;
      iov[0].iov_len = sizeof(header);
      iov[1].iov_base = &res;
      iov[1].iov_len = sizeof(uhid_get_report_reply_req);

      ssize_t bytes_written = writev(m_socket.GetFD(), iov, 2);
      if (bytes_written < 0) {
        m_socket.Close();
        hidp_throw_errno(errno, "writev failed");
      }
    }
  }
  catch (std::exception const &err) {
    XLOG_WARN("failed processing incoming client message. %s", err.what());
    return;
  }
}

Header
ProtocolReader::ReadHeader()
{
  Header header;
  int bytes_read = m_socket.Read(&header, sizeof(header));
  if (bytes_read < 0)
    hidp_throw_errno(-bytes_read, "failed reading header");
  HeaderFromNetwork(header);
  return header;
}

void
ProtocolReader::ProcessGetReportResponse(Header const &header, std::unique_ptr<InputDevice> &dev)
{
  uhid_get_report_reply_req req;
  m_socket.Read(&req, header.PacketSize);

  uhid_event e;
  e.type = UHID_GET_REPORT_REPLY;
  e.u.get_report_reply.id = le32toh(req.id);
  e.u.get_report_reply.err = le16toh(req.err);
  e.u.get_report_reply.size = le16toh(req.size);
  memcpy(e.u.get_report_reply.data, req.data, e.u.get_report_reply.size);

  ssize_t bytes_written = write(dev->GetFD(), &e, sizeof(e));
  if (bytes_written < 0)
    XLOG_WARN("failed to write GetReportReply. %s", strerror(errno));
}

void
ProtocolReader::ProcessIncomingServerMessage(std::vector< std::unique_ptr<InputDevice> > &local_devices)
{
  try {
    const Header header = ReadHeader();

    PacketType packet_type = static_cast<PacketType>(header.PacketType);
    if (packet_type == PacketType::Create) {
      ProcessCreate(header, local_devices);
      return;
    }

    if (packet_type == PacketType::Delete) {
      ProcessDelete(header, local_devices);
    }

    auto itr = std::find_if(std::begin(local_devices), std::end(local_devices), 
      [&header](const std::unique_ptr<InputDevice> &dev) {
        return header.ChannelId == dev->GetChannelId();
      });

    if (itr == std::end(local_devices)) {
      XLOG_WARN("got incoming message for channel %d, but can't find local device",
        header.ChannelId);
      return;
    }

    switch (packet_type) {
      case PacketType::GetReportRes:
      ProcessGetReportResponse(header, *itr);
      break;

      case PacketType::InputReport:
      ProcessInputReport(header, *itr);
      break;

      default:
      XLOG_WARN("unknown packet type:%d", static_cast<int>(packet_type));
      break;
    }

  }
  catch (std::exception const &err) {
    XLOG_WARN("error processining incoming server message. %s", err.what());
  }
}

void
ProtocolReader::ProcessDelete(Header const &header, std::vector<std::unique_ptr<InputDevice>> &local_devices)
{
  uhid_event e;
  e.type = UHID_DESTROY;

  XLOG_INFO("delete device on channel %d", header.ChannelId);

  auto itr = std::find_if(std::begin(local_devices), std::end(local_devices),
    [&header](std::unique_ptr<InputDevice> const &dev) {
      return dev->GetChannelId() == header.ChannelId;
    });

  if (itr == std::end(local_devices)) {
    XLOG_WARN("got request for channel %d, but there's no local device.", header.ChannelId);
    return;
  }

  std::unique_ptr<InputDevice>& dev = *itr;
  ssize_t bytes_written = write(dev->GetFD(), &e, sizeof(e));
  if (bytes_written < 0)
    hidp_throw_errno(errno, "failed to destroy virtual HID device");

  local_devices.erase(itr);
}

void
ProtocolReader::ProcessInputReport(Header const &header, std::unique_ptr<InputDevice> &dev)
{
  uhid_event e;
  m_socket.Read(&e.u.input2, header.PacketSize);

  e.type = UHID_INPUT2;
  e.u.input2.size = le16toh(e.u.input2.size);

  ssize_t bytes_written = write(dev->GetFD(), &e, sizeof(e));
  if (bytes_written < 0)
    hidp_throw_errno(errno, "failed to write input event");
}

void
ProtocolReader::ProcessCreate(Header const &header, std::vector<std::unique_ptr<InputDevice>> &local_devices)
{
  uhid_create2_req req;
  m_socket.Read(&req, header.PacketSize);

  req.rd_size = le16toh(req.rd_size);
  req.bus = le16toh(req.bus);
  req.vendor = le32toh(req.vendor);
  req.product = le32toh(req.product);
  req.version = le32toh(req.version);
  req.country = le32toh(req.country);

  #if 0
  XLOG_INFO("h.PacketSize  :%d", header.PacketSize);
  XLOG_INFO("h.ChannelId   :%d", header.ChannelId);
  XLOG_INFO("h.PacketType  :%d", header.PacketType);
  XLOG_INFO("req.name      :%s", req.name);
  XLOG_INFO("req.rd_size   :%d", req.rd_size);
  XLOG_INFO("req.bus       :%d", req.bus);
  XLOG_INFO("req.vendor    :%04x", req.vendor);
  XLOG_INFO("req.product   :%04x", req.product);
  XLOG_INFO("req.version   :%d", req.version);
  XLOG_INFO("req.country   :%d", req.country);
  #endif

  std::unique_ptr<InputDevice> new_device{ new InputDevice() };
  memcpy(new_device->m_name, req.name, std::min(sizeof(new_device->m_name), 
    sizeof(req.name)));

  new_device->m_channel_id = header.ChannelId;
  new_device->m_fd = open("/dev/uhid", O_RDWR);
  new_device->m_descriptor_size = req.rd_size;
  memcpy(new_device->m_descriptor, req.rd_data, req.rd_size);
  new_device->m_bus_type = req.bus;
  new_device->m_vendor_id = static_cast<int16_t>(req.vendor);
  new_device->m_product_id = static_cast<int16_t>(req.product);
  new_device->m_uuid = ""; // TODO encode uuid on server-side

  XLOG_INFO("creating new virtual HID for '%s' on channel %d", new_device->m_name,
    new_device->m_channel_id);

  uhid_event e;
  e.type = UHID_CREATE2;
  e.u.create2 = req;

  #if 0
  XLOG_INFO("size:%d", e.u.create2.rd_size);
  for (int i = 1; i <= e.u.create2.rd_size; ++i) {
    printf("0x%02x ", e.u.create2.rd_data[i - 1]);
    if (i % 16 == 0)
      printf("\n");
  }
  printf("\n");
  #endif

  ssize_t bytes_written = write(new_device->m_fd, &e, sizeof(e));
  if (bytes_written < 0)
    hidp_throw_errno(errno, "failed to create new virtual HID");
  local_devices.push_back(std::move(new_device));
}

void
ProtocolWriter::SendGetReportRequest(const std::unique_ptr<InputDevice> &dev)
{
  uhid_event e;
  ssize_t bytes_read = read(dev->GetFD(), &e, sizeof(e));
  if (bytes_read == -1) {
    XLOG_ERROR("failed to read GetReport request from uhid. %s", strerror(errno));
    return;
  }

  if (e.type != UHID_GET_REPORT)
    return;

  Header header;
  header.PacketSize = sizeof(uhid_get_report_req);
  header.ChannelId = dev->GetChannelId();
  header.PacketType = static_cast<int16_t>(PacketType::GetReportReq);
  HeaderToNetwork(header);

  #if 0
  XLOG_INFO("type:%d", e.type);
  XLOG_INFO("size:%d", static_cast<int>(bytes_read));
  XLOG_INFO("get_report.id:%d", e.u.get_report.id);
  XLOG_INFO("get_report.rnum:%d", e.u.get_report.rnum);
  XLOG_INFO("get_report.rtype:%d", e.u.get_report.rtype);
  #endif

  e.u.get_report.id = htole32(e.u.get_report.id);

  iovec iov[2];
  iov[0].iov_base = &header;
  iov[0].iov_len = sizeof(header);
  iov[1].iov_base = &e.u.get_report;
  iov[1].iov_len = sizeof(uhid_get_report_req);

  Send(iov, 2);
}
