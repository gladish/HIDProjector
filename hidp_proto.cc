
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
  XLOG_INFO("sending create");

  if (!m_socket.IsConnected())
    return;

  Header header;
  header.PacketSize = sizeof(uhid_create2_req);
  header.ChannelId = dev->ChannelId();
  header.PacketType = static_cast<int16_t>(PacketType::Create);
  HeaderToNetwork(header);

  uhid_create2_req req = {};
  req.bus = htole32(dev->GetBusType());
  req.vendor = htole32(dev->GetVendorId());
  req.product = htole32(dev->GetProductId());
  const std::string id = dev->GetId();
  memcpy(req.uniq, id.c_str(), id.size());
  dev->GetName(reinterpret_cast<char *>(req.name), sizeof(req.name));
  Buffer<uint32_t> descriptor = dev->GetDescriptor();
  req.rd_size = htole32(descriptor.Length);
  memcpy(req.rd_data, descriptor.Data, descriptor.Length);

  for (int i = 1; i <= req.rd_size; ++i) {
    printf("0x%02x ", req.rd_data[i -1]);
    if (i % 16 == 0)
      printf("\n");
  }
  printf("\n");

  DumpSendCreate(header, req);

  iovec iov[2];
  iov[0].iov_base = &header;
  iov[0].iov_len = sizeof(header);
  iov[1].iov_base = &req;
  iov[1].iov_len = sizeof(uhid_create2_req);

  XLOG_INFO("SendCreate");
  Send(iov, 2);
}

void
ProtocolWriter::SendDelete(const std::unique_ptr<InputDevice> &dev)
{
  if (!m_socket.IsConnected())
    return;

  Header header;
  header.PacketSize = 0;
  header.ChannelId = dev->ChannelId();
  header.PacketType = static_cast<int16_t>(PacketType::Delete);
  HeaderToNetwork(header);

  iovec iov[1];
  iov[0].iov_base = &header;
  iov[0].iov_len = sizeof(header);

  XLOG_INFO("SendDelete");
  Send(iov, 1);
}

void
ProtocolWriter::SendInputReport(const std::unique_ptr<InputDevice> &dev)
{
  if (!m_socket.IsConnected())
    return;

  Buffer<uint16_t> report = dev->GetReport();

  Header header;
  header.PacketSize = sizeof(report.Length) + report.Length;
  header.ChannelId = dev->ChannelId();
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
  ssize_t bytes_written = writev(m_socket.Descriptor(), v, n);
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
ProtocolReader::ProcessIncomingClientMessage(std::vector< std::unique_ptr<InputDevice> > &local_devices)
{
  try {
    const Header header = ReadHeader();
    if (header.PacketType == static_cast<int16_t>(PacketType::GetReportReq)) {
      auto itr = std::find_if(std::begin(local_devices), std::end(local_devices),
        [&header](std::unique_ptr<InputDevice> const &dev) {
          return dev->ChannelId() == header.ChannelId;
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

      char buff[256];
      buff[0] = req.rnum;

      int ret = ioctl((*itr)->Descriptor(), HIDIOCGFEATURE(256), buff);
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

      Header header;
      header.PacketSize = sizeof(uhid_get_report_reply_req);
      header.ChannelId = (*itr)->ChannelId();
      header.PacketType = static_cast<int16_t>(PacketType::GetReportRes);
      HeaderToNetwork(header);

      iovec iov[2];
      iov[0].iov_base = &header;
      iov[0].iov_len = sizeof(header);
      iov[1].iov_base = &res;
      iov[1].iov_len = sizeof(uhid_get_report_reply_req);

      ssize_t bytes_written = writev(m_socket.Descriptor(), iov, 2);
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
ProtocolReader::ProcessIncomingServerMessage(std::vector< std::unique_ptr<InputDevice> > &local_devices)
{
  try {
    const Header header = ReadHeader();

    PacketType packet_type = static_cast<PacketType>(header.PacketType);
    if (packet_type == PacketType::Create) {
      ProcessCreate(header, local_devices);
      return;
    }

    auto itr = std::find_if(std::begin(local_devices), std::end(local_devices), 
      [&header](const std::unique_ptr<InputDevice> &dev) {
        return header.ChannelId == dev->ChannelId();
      });

    if (itr == std::end(local_devices)) {
      XLOG_INFO("got incoming message for channel %d ,but can't find local device",
        header.ChannelId);
      return;
    }
  }
  catch (std::exception const &err) {
    XLOG_WARN("error processining incoming server message. %s", err.what());
  }
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

  XLOG_INFO("creating new virtual HID for '%s'", new_device->m_name);
  uhid_event e;
  e.type = UHID_CREATE2;
  e.u.create2 = req;

  XLOG_INFO("size:%d", e.u.create2.rd_size);
  for (int i = 1; i <= e.u.create2.rd_size; ++i) {
    printf("0x%02x ", e.u.create2.rd_data[i - 1]);
    if (i % 16 == 0)
      printf("\n");
  }
  printf("\n");

  ssize_t bytes_written = write(new_device->m_fd, &e, sizeof(e));
  if (bytes_written < 0)
    hidp_throw_errno(errno, "failed to create new virtual HID");
  else
    XLOG_INFO("bytes_written:%d", static_cast<int>(bytes_written));
  local_devices.push_back(std::move(new_device));
}

void
ProtocolWriter::SendGetReportRequest(const std::unique_ptr<InputDevice> &dev)
{
  Header header;
  header.PacketSize = sizeof(uhid_get_report_req);
  header.ChannelId = dev->ChannelId();
  header.PacketType = static_cast<int16_t>(PacketType::GetReportReq);
  HeaderToNetwork(header);

  uhid_event e;
  ssize_t bytes_read = read(dev->Descriptor(), &e, sizeof(e));
  if (bytes_read == -1) {
    XLOG_ERROR("failed to read GetReport request from uhid. %s", strerror(errno));
    return;
  }

  iovec iov[2];
  iov[0].iov_base = &header;
  iov[0].iov_len = sizeof(header);
  iov[1].iov_base = &e.u.get_report;
  iov[1].iov_len = sizeof(uhid_get_report_req);

  XLOG_INFO("SendGetReportRequeset");
  Send(iov, 2);

}
