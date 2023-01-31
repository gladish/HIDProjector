
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <fcntl.h>

#include <linux/hidraw.h>
#include <linux/version.h>
#include <linux/input.h>
#include <libudev.h>
#include <linux/uhid.h>

#include "hidp.h"

#include <algorithm>
#include <vector>

struct HIDRawMonitor {
  struct hidraw_report_descriptor desc;
  struct hidraw_devinfo info;
  int fd;
  struct udev_device *raw_dev;
  struct udev_device *hid_dev;
  char name[256];
  int16_t channel_id;
  char report_buff[256];
  ssize_t report_size;

  ssize_t read_feature(struct uhid_get_report_req &req, struct uhid_get_report_reply_req &res) {
    char buff[256];
    buff[0] = req.rnum;

    int ret = ioctl(fd, HIDIOCGFEATURE(256), buff);
    if (ret < 0) {
      int err = errno;
      XLOG_ERROR("failed to request feature from device. %s", strerror(err));
      return -err;
    }

    res.id = req.id;
    res.err = 0;
    res.size = ret;
    memcpy(res.data, buff, ret);

    return ret;
  }
};

class ConnectedClient {
public:
  ConnectedClient() : m_fd(-1) { }

  int fd() const
    { return m_fd; }

  void set_connected(int fd) {
    m_fd = fd;

    memset(&m_remote_endpoint, 0, sizeof(m_remote_endpoint));
    m_remote_endpoint_length = sizeof(m_remote_endpoint);
    getpeername(m_fd, (struct sockaddr *) &m_remote_endpoint, &m_remote_endpoint_length);
    // TODO: check length of m_remote_endpoint_length
    m_remote_endpoint.ss_family = AF_INET;

    XLOG_INFO("new client connection from%s", hipd_socketaddr_to_string(m_remote_endpoint)
      .c_str());
  }

  ssize_t send_report(HIDRawMonitor *mon);
  ssize_t send_create(HIDRawMonitor *mon);
  ssize_t send_delete(HIDRawMonitor *mon);

private:
  ssize_t send_packet(int16_t id, const void *buff, ssize_t count, PacketType p, enum uhid_event_type t);

private:
  socklen_t m_remote_endpoint_length;
  sockaddr_storage m_remote_endpoint;
  int m_fd;
};

struct HIDMonitorServer
{
public:
  HIDMonitorServer()
    : listen_fd(-1)
    , monitor_fd(-1)
    , udev(nullptr)
    , mon(nullptr)
  {
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr_size = sizeof(listen_addr);
  }

  void read_incoming_vhid_request() {
    HIDCommandPacketHeader header;
    int bytes_read = hidp_read_until(client.fd(), &header, sizeof(HIDCommandPacketHeader));
    if (bytes_read < 0) {
      XLOG_WARN("failed to read invoming VHID request. %s", strerror(-bytes_read));
      return;
    }

    hid_command_packet_header_from_network(&header);

    struct uhid_get_report_req req;
    bytes_read = hidp_read_until(client.fd(), &req, sizeof(req));
    if (bytes_read < 0) {
      XLOG_WARN("failed to read VHID request. %s", strerror(-bytes_read));
    }

    auto itr = std::find_if(std::begin(active_devices), std::end(active_devices), 
      [&header](HIDRawMonitor *mon)
      {
        return mon->channel_id == header.channel_id;
      });

    if (itr == std::end(active_devices)) {
      XLOG_WARN("failed to find HIDRawMonitor for channel:%d", header.channel_id);
      return;
    }

    struct uhid_get_report_reply_req res;
    ssize_t n = (*itr)->read_feature(req, res);

    res.id = htole32(res.id);
    res.err = htole16(res.err);
    res.size = htole16(res.size);

    header.packet_size = (n + sizeof(HIDCommandPacketHeader) + 8);
    header.packet_type = PacketTypeGetReportResponse;
    header.event_type = UHID_GET_REPORT_REPLY;
    hid_command_packet_header_to_network(&header);

    struct iovec iov[2];
    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = &res;
    iov[1].iov_len = 8 + n;

    ssize_t bytes_written = writev(client.fd(), iov, 2);
    if (bytes_written < 0) {
      int err = errno;
      XLOG_WARN("failed to write get_report reply. %s", strerror(err));
      return;
    }
    else {
      XLOG_INFO("bytes_written:%d", bytes_written);
    }
  }

  int listen_fd;
  int monitor_fd;
  ConnectedClient client;
  struct sockaddr_storage listen_addr;
  socklen_t listen_addr_size;
  struct udev *udev;
  struct udev_monitor *mon;
  std::vector<HIDRawMonitor *> active_devices;
public:
  int do_accept() {
    sockaddr_storage remote_addr;
    socklen_t remote_addr_size = sizeof(sockaddr_storage);
    int fd = accept(listen_fd, (struct sockaddr *) &remote_addr, &remote_addr_size);
    if (fd == 1) {
      XLOG_ERROR("failed to accept on listener socket. %s", strerror(errno));
      return -1;
    }
    return fd;
  }
};

static int16_t next_hidraw_monitor_id = 1001;

HIDMonitorServer *hid_monitor_server_new(const char *listen_addr, int listen_port);
void              hid_monitor_server_accept(HIDMonitorServer *server);
void              hid_monitor_server_create_or_delete(HIDMonitorServer *server);

HIDRawMonitor    *hidraw_monitor_from_udev(struct udev_device *dev);
std::vector<HIDRawMonitor*> hidraw_monitor_new(struct udev *dev);
int               hidraw_monitor_read_report(HIDRawMonitor *hidrwaw);
void              hidraw_monitor_free(HIDRawMonitor *hidraw);

int main(int argc, char *argv[])
{
  int ret;
  int watch_fd;

  HIDMonitorServer *server = hid_monitor_server_new(nullptr, 10020);

  while (true) {
    fd_set read_fds;
    FD_ZERO(&read_fds);

    int max_fd = -1;
    hidp_push_fd(&read_fds, server->listen_fd, &max_fd);
    hidp_push_fd(&read_fds, server->monitor_fd, &max_fd);

    for (HIDRawMonitor *mon : server->active_devices)
      hidp_push_fd(&read_fds, mon->fd, &max_fd);

    if (server->client.fd() != -1)
      hidp_push_fd(&read_fds, server->client.fd(), &max_fd);

    int ret = select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr);
    if (ret == -1) {
      XLOG_WARN("select:%s", strerror(errno));
      continue;
    }

    if ((server->client.fd() != -1) && FD_ISSET(server->client.fd(), &read_fds)) {
      server->read_incoming_vhid_request();
    }

    if (FD_ISSET(server->listen_fd, &read_fds))
      hid_monitor_server_accept(server);

    if (FD_ISSET(server->monitor_fd, &read_fds)) {
      hid_monitor_server_create_or_delete(server);
    }

    for (auto begin = std::begin(server->active_devices), end = std::end(server->active_devices);
      begin != end; ++begin)
    {
      HIDRawMonitor *mon = *begin;
      if (FD_ISSET(mon->fd, &read_fds)) {
        int ret = hidraw_monitor_read_report(mon);
        if (ret > 0) {
          server->client.send_report(mon);
        }
        else {
          server->client.send_delete(mon);
          delete mon;
          begin = server->active_devices.erase(begin);
          break;
        }
      }
    }
  }

  return 0;
}

ssize_t ConnectedClient::send_report(HIDRawMonitor *mon)
{
  if (m_fd == -1)
    return -ENOTCONN;

  int16_t packet_size = (int16_t) (10 + mon->report_size);
  int16_t packet_type = (int16_t) PacketTypeReport;
  int16_t event_type = UHID_INPUT2;

  packet_size = htole16(packet_size);
  packet_type = htole16(packet_type);
  event_type = htole16(event_type);
  int16_t channel_id = htole16(mon->channel_id);

  // size
  int16_t input_size = htole16( (int16_t) mon->report_size );

  struct iovec iov[6];
  iov[0].iov_base = &packet_size;
  iov[0].iov_len = sizeof(packet_size);
  iov[1].iov_base = &channel_id;
  iov[1].iov_len = sizeof(channel_id);
  iov[2].iov_base = &packet_type;
  iov[2].iov_len = sizeof(packet_type);
  iov[3].iov_base = &event_type;
  iov[3].iov_len = sizeof(event_type);
  iov[4].iov_base = &input_size;
  iov[4].iov_len = sizeof(input_size);
  iov[5].iov_base = mon->report_buff;
  iov[5].iov_len = mon->report_size;

  #if 0
  uint8_t *ptr = (uint8_t *) mon->report_buff;
  for (int i = 0; i < mon->report_size; ++i)
    printf("%02x ", (uint8_t) ptr[i]);
  printf("\n");
  #endif

  ssize_t bytes_written = writev(m_fd, iov, 6);
  if (bytes_written < 0) {
    int err = errno;
    XLOG_ERROR("writev:%s", strerror(err));
    close(m_fd);
    m_fd = -1;
    return -err;
  }

  return bytes_written;
}

ssize_t
ConnectedClient::send_packet(int16_t id, const void *buff, ssize_t count, PacketType p, enum uhid_event_type t)
{
  if (m_fd == -1)
    return -ENOTCONN;

  // amount of data about to be sent
  // 2 bytes size of packet
  // 2 bytes device id
  // 2 bytes PacketType
  // 2 bytes uhid_event_type
  // x bytes payload
  int16_t packet_size = (int16_t) (6 + count);
  int16_t packet_type = (int16_t) p;
  int16_t event_type = (int16_t) t;

  packet_size = htole16(packet_size);
  packet_type = htole16(packet_type);
  event_type = htole16(event_type);
  id = htole16(id);

  struct iovec iov[5];
  iov[0].iov_base = &packet_size;
  iov[0].iov_len = sizeof(packet_size);
  iov[1].iov_base = &id;
  iov[1].iov_len = sizeof(id);
  iov[2].iov_base = &packet_type;
  iov[2].iov_len = sizeof(packet_type);
  iov[3].iov_base = &event_type;
  iov[3].iov_len = sizeof(event_type);
  iov[4].iov_base = (void *) buff;
  iov[4].iov_len = count;

  ssize_t bytes_written = writev(m_fd, iov, 3);
  if (bytes_written < 0) {
    int err = errno;
    XLOG_WARN("failed to write packet. %s", strerror(err));
    close(m_fd);
    m_fd = -1;
    return -err;
  }

  return bytes_written;
}

HIDRawMonitor *hidraw_monitor_from_udev(struct udev_device *dev)
{
  HIDRawMonitor *mon = new HIDRawMonitor();
  memset(mon, 0, sizeof(HIDRawMonitor));
  mon->channel_id = next_hidraw_monitor_id++;
  mon->raw_dev = udev_device_ref(dev);
  mon->hid_dev = udev_device_get_parent_with_subsystem_devtype(
    mon->raw_dev,
    "hid",
    nullptr);

  XLOG_INFO(" --- new HID device ---");
  hidp_udev_device_dump(mon->hid_dev);

  const char *dev_node = udev_device_get_devnode(mon->raw_dev);

  mon->fd = open(dev_node, O_RDWR);
  if (mon->fd == -1) {
    XLOG_ERROR("open(%s):%s", dev_node, strerror(errno));
    return nullptr;
  }

  XLOG_INFO("opened %s (fd:%d)", dev_node, mon->fd);

  int ret = ioctl(mon->fd,HIDIOCGRAWINFO, &mon->info);
  if (ret < 0) {
    XLOG_ERROR("failed to get device info. %s", strerror(errno));
    return nullptr;
  }

  ret = ioctl(mon->fd, HIDIOCGRDESCSIZE, &mon->desc.size);
  if (ret < 0) {
    XLOG_ERROR("failed to get descriptor size. %s", strerror(errno));
    return nullptr;
  }

  ret = ioctl(mon->fd, HIDIOCGRDESC, &mon->desc);
  if (ret < 0) {
    XLOG_ERROR("failed to get descriptor. %s", strerror(errno));
    return nullptr;
  }

  ret = ioctl(mon->fd, HIDIOCGRAWNAME(255), mon->name);
  if (ret < 0) {
    XLOG_ERROR("failed to get name. %s", strerror(errno));
    return nullptr;
  }

  XLOG_INFO("bus_type: %s", hidp_bus_to_string(mon->info.bustype));
  XLOG_INFO("vendor  : 0x%04hx", mon->info.vendor);
  XLOG_INFO("product : 0x%04hx", mon->info.product);
  XLOG_INFO("name    : %s", mon->name);
  XLOG_INFO(" --- end new HID device ---");

  return mon;
}

int hidraw_monitor_read_report(HIDRawMonitor *hidraw)
{
  memset(hidraw->report_buff, 0, sizeof(hidraw->report_buff));

  ssize_t n = read(hidraw->fd, hidraw->report_buff, sizeof(hidraw->report_buff));
  if (n > 0) {
    // XLOG_INFO("read report size:%d", (int) n);
    hidraw->report_size = n;
  }
  else {
    int err = errno;
    XLOG_WARN("read_report:%s", strerror(err));
    return -err;
  }

  return n;
}

ssize_t ConnectedClient::send_create(HIDRawMonitor *mon)
{
  if (m_fd == -1) {
    XLOG_INFO("can't send, not connected");
    return -ENOTCONN;
  }

   // amount of data about to be sent
  // 2 bytes size of packet
  // 2 bytes PacketType
  // 2 bytes uhid_event_type
  // x bytes payload
  int16_t packet_size = (int16_t) (8 + sizeof(struct uhid_create2_req));
  int16_t packet_type = (int16_t) (PacketTypeCreate);
  int16_t event_type = (int16_t) UHID_CREATE2;

  packet_size = htole16(packet_size);
  packet_type = htole16(packet_type);
  event_type = htole16(event_type);
  int16_t channel_id = htole16(mon->channel_id);

  struct uhid_create2_req req;
  memset(&req, 0, sizeof(req));
  memcpy(req.name, mon->name, sizeof(req.name));
  req.rd_size = mon->desc.size;
  memcpy(req.rd_data, mon->desc.value, req.rd_size);
  req.bus = mon->info.bustype;
  req.vendor = mon->info.vendor;
  req.product = mon->info.product;

  req.rd_size = htole16(req.rd_size);
  req.bus = htole16(req.bus);
  req.vendor = htole32(req.vendor);
  req.product = htole32(req.product);

  struct iovec iov[5];
  iov[0].iov_base = &packet_size;
  iov[0].iov_len = sizeof(packet_size);
  iov[1].iov_base = &channel_id;
  iov[1].iov_len = sizeof(channel_id);
  iov[2].iov_base = &packet_type;
  iov[2].iov_len = sizeof(packet_type);
  iov[3].iov_base = &event_type;
  iov[3].iov_len = sizeof(event_type);
  iov[4].iov_base = &req;
  iov[4].iov_len = sizeof(req);

  ssize_t bytes_written = writev(m_fd, iov, 5);
  if (bytes_written < 0) {
    int err = errno;
    XLOG_ERROR("writev:%s", strerror(err));
    close(m_fd);
    m_fd = -1;
    return -err;
  }

  return bytes_written;
}

ssize_t ConnectedClient::send_delete(HIDRawMonitor *mon)
{
  if (m_fd == -1)
    return -ENOTCONN;

  HIDCommandPacketHeader pkt;
  pkt.packet_size = sizeof(HIDCommandPacketHeader);
  pkt.channel_id = mon->channel_id;
  pkt.packet_type = PacketTypeDelete;
  pkt.event_type = UHID_DESTROY;
  hid_command_packet_header_to_network(&pkt);

  struct iovec iov[4];
  iov[0].iov_base = &pkt.packet_size;
  iov[0].iov_len = sizeof(pkt.packet_size);
  iov[1].iov_base = &pkt.channel_id;
  iov[1].iov_len = sizeof(pkt.channel_id);
  iov[2].iov_base = &pkt.packet_type;
  iov[2].iov_len = sizeof(pkt.packet_type);
  iov[3].iov_base = &pkt.event_type;
  iov[3].iov_len = sizeof(pkt.event_type);

  ssize_t bytes_written = writev(m_fd, iov, 4);
  if (bytes_written < 0) {
    int err = errno;
    XLOG_WARN("error sending UHID_DESTROY. %s", strerror(err));
    close(m_fd);
    m_fd = -1;
    return -err;
  }

  return bytes_written;
}

int parse_uevent_info(const char *uevent, unsigned *bus_type,
	unsigned short *vendor_id, unsigned short *product_id,
	char **serial_number_utf8, char **product_name_utf8)
{
	char tmp[1024];
	size_t uevent_len = strlen(uevent);
	if (uevent_len > sizeof(tmp) - 1)
		uevent_len = sizeof(tmp) - 1;
	memcpy(tmp, uevent, uevent_len);
	tmp[uevent_len] = '\0';

	char *saveptr = nullptr;
	char *line;
	char *key;
	char *value;

	int found_id = 0;
	int found_serial = 0;
	int found_name = 0;

	line = strtok_r(tmp, "\n", &saveptr);
	while (line != nullptr) {
		/* line: "KEY=value" */
		key = line;
		value = strchr(line, '=');
		if (!value) {
			goto next_line;
		}
		*value = '\0';
		value++;

		if (strcmp(key, "HID_ID") == 0) {
			/**
			 *        type vendor   product
			 * HID_ID=0003:000005AC:00008242
			 **/
			int ret = sscanf(value, "%x:%hx:%hx", bus_type, vendor_id, product_id);
			if (ret == 3) {
				found_id = 1;
			}
		} else if (strcmp(key, "HID_NAME") == 0) {
			/* The caller has to free the product name */
			*product_name_utf8 = strdup(value);
			found_name = 1;
		} else if (strcmp(key, "HID_UNIQ") == 0) {
			/* The caller has to free the serial number */
			*serial_number_utf8 = strdup(value);
			found_serial = 1;
		}

next_line:
		line = strtok_r(nullptr, "\n", &saveptr);
	}

	return (found_id && found_name && found_serial);
}

std::vector<HIDRawMonitor *> hidraw_monitor_new(struct udev *udev)
{
  std::vector< HIDRawMonitor *> active_devices;

  struct udev_enumerate *e = udev_enumerate_new(udev);
  udev_enumerate_add_match_subsystem(e, "hidraw");
  udev_enumerate_scan_devices(e);

  struct udev_list_entry *devices = udev_enumerate_get_list_entry(e);

  XLOG_INFO("scanning for any existing HIDs");
  for (struct udev_list_entry *itr = devices; itr; itr = udev_list_entry_get_next(itr)) {
    const char *sysfs_path = udev_list_entry_get_name(itr);
    struct udev_device *raw_dev = udev_device_new_from_syspath(udev, sysfs_path);
    if (raw_dev) {
      active_devices.push_back( hidraw_monitor_from_udev(raw_dev) );
      udev_device_unref(raw_dev);
    }
  }
  udev_enumerate_unref(e);
  XLOG_INFO("new HID scan complete");

  return active_devices;
}

HIDMonitorServer *hid_monitor_server_new(const char *listen_addr, int listen_port)
{
  HIDMonitorServer *server = new HIDMonitorServer();

  struct sockaddr_in *v4 = (struct sockaddr_in *) &server->listen_addr;
  memset(&server->listen_addr, 0, sizeof(&server->listen_addr));
  v4->sin_family = AF_INET;
  v4->sin_addr.s_addr = htonl(INADDR_ANY);
  v4->sin_port = htons(listen_port);
  server->listen_addr_size = sizeof(struct sockaddr_in);

  XLOG_INFO("creating listener socket");
  server->listen_fd = socket(AF_INET,  SOCK_STREAM, 0);
  if (server->listen_fd == -1) {
    XLOG_ERROR("socket:%s", strerror(errno));
    return nullptr;
  }
  else
    XLOG_INFO("server listener socket fd:%d", server->listen_fd);

  int optval = 1;
  if (setsockopt(server->listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) < 0) {
    XLOG_ERROR("setsockopt:%s", strerror(errno));
  }

  XLOG_INFO("binding listener to:");
  int ret = bind(server->listen_fd, (struct sockaddr *) &server->listen_addr, server->listen_addr_size);
  if (ret == -1) {
    close(server->listen_fd);
    XLOG_ERROR("bind:%s", strerror(errno));
    return nullptr;
  }

  ret = listen(server->listen_fd, 1);
  if (ret == -1) {
    close(server->listen_fd);
    XLOG_ERROR("listen:%s", strerror(errno));
    return nullptr;
  }

  server->udev = udev_new();
  server->mon = udev_monitor_new_from_netlink(server->udev, "udev");
  udev_monitor_filter_add_match_subsystem_devtype(server->mon, "hidraw", nullptr);
  udev_monitor_enable_receiving(server->mon);
  server->monitor_fd = udev_monitor_get_fd(server->mon);

  XLOG_INFO("resetting active devices list");
  server->active_devices = hidraw_monitor_new(server->udev);

  XLOG_INFO("server creation completed");

  return server;
}

void hid_monitor_server_accept(HIDMonitorServer *server)
{
  int fd = server->do_accept();
  server->client.set_connected(fd);
  for (HIDRawMonitor *mon : server->active_devices)
    server->client.send_create(mon);
}

void hid_monitor_server_create_or_delete(HIDMonitorServer *server)
{
  struct udev_device *dev = udev_monitor_receive_device(server->mon);
  if (!dev) {
    XLOG_DEBUG("udev_monitor_receive_device returned NULL");
    return;
  }

  const char *action = udev_device_get_action(dev);
  if (!action) {
    XLOG_DEBUG("udev_device_get_action returned NULL action");
    return;
  }

  if (strcasecmp(action, "add") == 0) {
    XLOG_INFO("add:%s", udev_device_get_devnode(dev));
    HIDRawMonitor *mon = hidraw_monitor_from_udev(dev);
    server->active_devices.push_back(mon);
    server->client.send_create(mon);
  }
  else if (strcasecmp(action, "remove") == 0) {
    XLOG_INFO("remove:%s", udev_device_get_devnode(dev));
    for (auto begin = std::begin(server->active_devices), end = std::end(server->active_devices);
      begin != end; ++begin)
    {
      HIDRawMonitor *mon = *begin;
      const char *devnode = udev_device_get_devnode(mon->raw_dev);
      if (strcmp(devnode, udev_device_get_devnode(dev)) == 0) {
        server->client.send_delete(mon);
        begin = server->active_devices.erase(begin);
        break;
      }
    }
  }
  udev_device_unref(dev);
}

void hidraw_monitor_free(HIDRawMonitor *hidraw)
{
  /*
  if (hidraw->raw_dev)
    udev_device_unref(hidraw->raw_dev);
  */

  if (hidraw->fd > 0)
    close(hidraw->fd);

  free(hidraw);
}
