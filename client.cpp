#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/uhid.h>

#include <algorithm>
#include <vector>

#include "hidp.h"

class VirtualHID {
public:
  VirtualHID(int16_t channel_id)
    : m_channel_id(channel_id) {
    m_uhid_fd = open("/dev/uhid", O_RDWR | O_CLOEXEC);
    XLOG_INFO("created new VHID device with fd:%d device_id:%d", m_uhid_fd,
      channel_id);
  } 
  ~VirtualHID() {
    XLOG_INFO("deleting VHID device with fd:%d device_id:%d", m_uhid_fd,
      m_channel_id);
    if (m_uhid_fd > 0)
      close(m_uhid_fd);
  }

  ssize_t write_event(const uhid_event *e) {
    ssize_t bytes_written = write(m_uhid_fd, e, sizeof(uhid_event));
    if (bytes_written < 0) {
      int err = errno;
      XLOG_INFO("write failed with: %z. %s", bytes_written, strerror(err));
      return -err;
    }
    return bytes_written;
  }

  int16_t channel_id() const { return m_channel_id; }
  int uhid_fd() const { return m_uhid_fd; }
private:
  int16_t m_channel_id;
  int m_uhid_fd;
};

struct HIDMonitorClient {
public:
  HIDMonitorClient(const char *server_addr, int server_port) {
    m_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (m_sock == -1) {
      XLOG_FATAL("socket:%s", strerror(errno));
    }

    struct sockaddr_in *v4 = reinterpret_cast<struct sockaddr_in *>(&m_remote_endpoint);

    int ret = inet_pton(AF_INET, server_addr, &v4->sin_addr);
    if (ret == -1)
      XLOG_FATAL("inet_pton:%s", strerror(errno));

    v4->sin_port = htons(server_port);
    v4->sin_family = AF_INET;
    m_remote_endpoint_size = sizeof(struct sockaddr_in);

    ret = connect(m_sock, reinterpret_cast<const struct sockaddr *>(&m_remote_endpoint), m_remote_endpoint_size);
    if (ret == -1)
      XLOG_FATAL("connect:%s", strerror(errno));
  }

  inline const HIDCommandPacketHeader *header() const {
    return reinterpret_cast<const HIDCommandPacketHeader *>(&(m_read_buffer[0]));
  }

  inline HIDCommandPacketHeader *header() {
    return reinterpret_cast<HIDCommandPacketHeader *>(&(m_read_buffer[0]));
  }

  template<class TData>
  inline const TData data() const {
    const void *p = &(m_read_buffer[sizeof(HIDCommandPacketHeader)]);
    return reinterpret_cast<const TData>(p);
  }

  void add_vhid(int16_t channel_id) {
    VirtualHID *vhid = new VirtualHID(channel_id);
    XLOG_INFO("adding new VHID with device id:%d", channel_id);

    const struct uhid_create2_req *req = data<const struct uhid_create2_req *>();
    struct uhid_event e;
    e.type = UHID_CREATE2;
    e.u.create2 = *req;

    ssize_t bytes_written = vhid->write_event(&e);
    if (bytes_written < 0) {
      int err = errno;
      XLOG_INFO("failed to write UHID_CREATE2. %s", strerror(err));
    }
    XLOG_INFO("VHID for '%s' created sucessfully", e.u.create2.name);
    m_vhids.push_back(vhid);
  }

  void remove_vhid(int16_t channel_id) {
    XLOG_INFO("removing VHID with id:%d", channel_id);
    auto itr = std::find_if(std::begin(m_vhids), std::end(m_vhids), [&channel_id](const VirtualHID *item) {
        return item->channel_id() == channel_id;
      });
    if (itr == std::end(m_vhids)) {
      XLOG_WARN("failed to find VHID with id:%d", channel_id);
      return;
    }

    VirtualHID *vhid = *itr;

    struct uhid_event e;
    e.type = UHID_DESTROY;

    ssize_t bytes_written = vhid->write_event(&e);
    if (bytes_written < 0) {
      XLOG_INFO("failed to send UHID_DELETE. %s", strerror(errno));
    }
    delete vhid;
    m_vhids.erase(itr);
    XLOG_INFO("VHID removed");
  }

  void submit_report(int16_t channel_id) {
    auto itr = std::find_if(std::begin(m_vhids), std::end(m_vhids), [&channel_id](const VirtualHID *item) {
        return item->channel_id() == channel_id;
      });

    if (itr == std::end(m_vhids)) {
      XLOG_INFO("failed to find VHID with id:%d", channel_id);
      return;
    }

    VirtualHID *vhid = *itr;

    const struct uhid_input2_req *req = data<const struct uhid_input2_req *>();
    struct uhid_event e;
    e.type = UHID_INPUT2;
    e.u.input2 = *req;

    ssize_t bytes_written = vhid->write_event(&e);
    if (bytes_written < 0) {
      XLOG_INFO("TODO: handle write failed");
    }
  }

  int fd() const
    { return m_sock; }

  int read_next_packet() {
    memset(m_read_buffer, 0, sizeof(m_read_buffer));

    const int sizeof_header = static_cast<int>(sizeof(HIDCommandPacketHeader));

    int bytes_read = hidp_read_until(m_sock, &m_read_buffer[0], sizeof_header);
    if (bytes_read < 0) {
      XLOG_ERROR("error reading packet header:%s", strerror(-bytes_read));
      return bytes_read;
    }

    HIDCommandPacketHeader *header = this->header();
    hid_command_packet_header_from_network(header);

    // read remainder of packet
    bytes_read = hidp_read_until(m_sock, &m_read_buffer[sizeof_header], (header->packet_size - sizeof_header));
    if (bytes_read < 0) {
      XLOG_ERROR("error reading packet body. %s", strerror(-bytes_read));
      return -bytes_read;
    }

    return bytes_read;
  }

  void push_vhid_fds(fd_set *set, int *max_fd) {
    for  (VirtualHID *vhid : m_vhids) {
      hidp_push_fd(set, vhid->uhid_fd(), max_fd);
    }
  }

  void check_vhid_fds(fd_set *set, int server_fd) {
    for (VirtualHID *vhid : m_vhids) {
      if (FD_ISSET(vhid->uhid_fd(), set)) {
        // TODO: kernel is asking for report, fwd to server
        struct uhid_event e;
        memset(&e, 0, sizeof(e));
        ssize_t bytes_read = read(vhid->uhid_fd(), &e, sizeof(e));
        XLOG_INFO("read from kernel:%d", (int) bytes_read);
        XLOG_INFO("type:%d", e.type);
        if  (e.type == UHID_GET_REPORT) {
          XLOG_INFO("id      :%d", e.u.get_report.id);
          XLOG_INFO("rnum    :%d", e.u.get_report.rnum);
          XLOG_INFO("rtype   :%d", e.u.get_report.rtype);
        }
      }
    }
  }

private:
  int m_sock;
  socklen_t m_remote_endpoint_size;
  sockaddr_storage m_remote_endpoint;
  char m_read_buffer[sizeof(HIDCommandPacketHeader) + sizeof(struct uhid_event)];
  std::vector< VirtualHID *> m_vhids;
};

int main(int argc, char *argv[])
{
  int ret;

  HIDMonitorClient *clnt = new HIDMonitorClient("10.0.0.133", 10020);
  if (!clnt)
    exit(1);

  while (true) {
    fd_set read_fds;
    FD_ZERO(&read_fds);

    int max_fd = -1;
    hidp_push_fd(&read_fds, clnt->fd(), &max_fd);
    clnt->push_vhid_fds(&read_fds, &max_fd);

    int ret = select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr);
    if (FD_ISSET(clnt->fd(), &read_fds)) {
      ret = clnt->read_next_packet();
      if (ret < 0) {
        XLOG_ERROR("failed to read");
        exit(1);
      }
      const HIDCommandPacketHeader *pkt = clnt->header();
      switch (pkt->packet_type) {
        case PacketTypeCreate:
          clnt->add_vhid(pkt->channel_id);
          break;
        case PacketTypeDelete:
          clnt->remove_vhid(pkt->channel_id);
          break;
        case PacketTypeReport:
          clnt->submit_report(pkt->channel_id);
          break;
        default:
          break;
      }
    }

    clnt->check_vhid_fds(&read_fds, clnt->fd());
  }

  return 0;
}
