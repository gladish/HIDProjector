
#include "hidp_common.h"
#include "hidp_proto.h"

#include <memory>

#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <linux/uhid.h>

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
  BufferReference<uint32_t> descriptor = dev->GetDescriptor();
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

  Send(iov, 1);
}

void
ProtocolWriter::SendInputReport(const std::unique_ptr<InputDevice> &dev)
{
  if (!m_socket.IsConnected())
    return;

  BufferReference<int16_t> report = dev->GetReport();

  Header header;
  header.PacketSize = sizeof(report.Length) + report.Length;
  header.ChannelId = dev->ChannelId();
  header.PacketType = static_cast<int16_t>(PacketType::InputReport);
  HeaderToNetwork(header);

  iovec iov[3];
  iov[0].iov_base = &header;
  iov[0].iov_len = sizeof(header);
  iov[1].iov_base = &report.Length;
  iov[1].iov_len = sizeof(report.Length);
  iov[2].iov_base = const_cast<uint8_t *>(report.Data);
  iov[2].iov_len = report.Length;

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
  XLOG_INFO("writev:%d", static_cast<int>(bytes_written));
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
ProtocolReader::ProcessIncomingClientMessage()
{
  try {
    const Header header = ReadHeader();
    if (header.PacketType == static_cast<int16_t>(PacketType::GetReportReq)) {
      uhid_get_report_req req;
      m_socket.Read(&req, header.PacketSize);

      XLOG_INFO("finish processing get report request");

      // TODO: find the InputDevice associated with the channel
      // do the ioctl() to get report
      // send back to m_socket
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
  const Header header = ReadHeader();
  auto itr = std::find_if(std::begin(local_devices), std::end(local_devices), 
    [&header](const std::unique_ptr<InputDevice> &dev) {
      return header.ChannelId == dev->ChannelId();
    });

  PacketType packet_type = static_cast<PacketType>(header.PacketType);
}

void
ProtocolWriter::SendGetReportRequest(const std::unique_ptr<InputDevice> &dev)
{
}
