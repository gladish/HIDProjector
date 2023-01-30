
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

typedef struct _HIDRawMonitor HIDRawMonitor;
struct _HIDRawMonitor {
  struct hidraw_report_descriptor desc;
  struct hidraw_devinfo info;
  int fd;
  struct udev_device *raw_dev;
  struct udev_device *hid_dev;
  char name[256];
  int16_t device_id;
  char report_buff[256];
  ssize_t report_size;
  struct _HIDRawMonitor *next;
};

typedef struct _ConnectedClient ConnectedClient;
struct _ConnectedClient {
  int fd;
  socklen_t remote_endpoint_size;
  struct sockaddr_storage remote_endpoint;
};

typedef struct _HIDMonitorServer HIDMonitorServer;
struct _HIDMonitorServer
{
  int listen_fd;
  int monitor_fd;
  ConnectedClient *client;
  HIDRawMonitor *locally_active_hid_devices;
  struct sockaddr_storage listen_addr;
  socklen_t listen_addr_size;
  struct udev *udev;
  struct udev_monitor *mon;
};

static int16_t next_hidraw_monitor_id = 1001;

HIDMonitorServer *hid_monitor_server_new(const char *listen_addr, int listen_port);
void              hid_monitor_server_accept(HIDMonitorServer *server);
void              hid_monitor_server_create_or_delete(HIDMonitorServer *server);

HIDRawMonitor    *hidraw_monitor_from_udev(HIDRawMonitor *hidraw, struct udev_device *dev);
HIDRawMonitor    *hidraw_monitor_new(struct udev *dev);
int               hidraw_monitor_read_report(HIDRawMonitor *hidrwaw);
void              hidraw_monitor_free(HIDRawMonitor *hidraw);
HIDRawMonitor    *hidraw_monitor_free_node(HIDRawMonitor *list, HIDRawMonitor *node);

void              client_send_report(ConnectedClient *clnt, HIDRawMonitor *hidraw);
void              client_send_create(ConnectedClient *clnt, HIDRawMonitor *hidraw);
void              client_send_delete(ConnectedClient *clnt, HIDRawMonitor *hidraw);
void              client_send_packet(
                      ConnectedClient      *clnt,
                      int16_t               id,
                      const void           *buff,
                      ssize_t               count,
                      PacketType            packet_type,
                      enum uhid_event_type  event_type);


int main(int argc, char *argv[])
{
  int ret;
  int watch_fd;

  HIDMonitorServer *server = hid_monitor_server_new(NULL, 10020);

  while (true) {
    fd_set read_fds;
    FD_ZERO(&read_fds);

    int max_fd = -1;
    hidp_push_fd(&read_fds, server->listen_fd, &max_fd);
    hidp_push_fd(&read_fds, server->monitor_fd, &max_fd);
    for (HIDRawMonitor *dev  = server->locally_active_hid_devices; dev; dev = dev->next)
      hidp_push_fd(&read_fds, dev->fd, &max_fd);

    int ret = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
    if (ret == -1) {
      XLOG_WARN("select:%s", strerror(errno));
      continue;
    }

    if (FD_ISSET(server->listen_fd, &read_fds))
      hid_monitor_server_accept(server);

    if (FD_ISSET(server->monitor_fd, &read_fds))
      hid_monitor_server_create_or_delete(server);

    for (HIDRawMonitor *mon = server->locally_active_hid_devices; mon; mon = mon->next) {
      if (FD_ISSET(mon->fd, &read_fds)) {
        int ret = hidraw_monitor_read_report(mon);
        if (ret > 0)
          client_send_report(server->client, mon);
        else {
          client_send_delete(server->client, mon);
          server->locally_active_hid_devices = hidraw_monitor_free_node(
            server->locally_active_hid_devices, mon);
          break;
        }
      }
    }
  }

  return 0;
}

void
client_send_report(ConnectedClient *clnt, HIDRawMonitor *mon)
{
  if (!clnt)
    return;

  int16_t packet_size = (int16_t) (10 + mon->report_size);
  int16_t packet_type = (int16_t) PacketTypeReport;
  int16_t event_type = UHID_INPUT2;

  packet_size = htole16(packet_size);
  packet_type = htole16(packet_type);
  event_type = htole16(event_type);
  int16_t device_id = htole16(mon->device_id);

  // size
  int16_t input_size = htole16( (int16_t) mon->report_size );

  struct iovec iov[6];
  iov[0].iov_base = &packet_size;
  iov[0].iov_len = sizeof(packet_size);
  iov[1].iov_base = &device_id;
  iov[1].iov_len = sizeof(device_id);
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

  ssize_t bytes_written = writev(clnt->fd, iov, 6);
  if (bytes_written < 0)
    XLOG_ERROR("writev:%s", strerror(errno));
  // else
  //  XLOG_INFO("writev:%d", (int) bytes_written);
}

void
client_send_packet(ConnectedClient *clnt, int16_t id, const void *buff, ssize_t count, PacketType p, enum uhid_event_type t)
{
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

  ssize_t bytes_written = writev(clnt->fd, iov, 3);
}

HIDRawMonitor *hidraw_monitor_from_udev(HIDRawMonitor *list, struct udev_device *dev)
{
  HIDRawMonitor *mon = calloc(1, sizeof(HIDRawMonitor));
  mon->device_id = next_hidraw_monitor_id++;
  mon->raw_dev = udev_device_ref(dev);
  mon->hid_dev = udev_device_get_parent_with_subsystem_devtype(
    mon->raw_dev,
    "hid",
    NULL);

  XLOG_INFO(" --- new HID device ---");
  hidp_udev_device_dump(mon->hid_dev);

  const char *dev_node = udev_device_get_devnode(mon->raw_dev);

  mon->fd = open(dev_node, O_RDWR | O_CLOEXEC);
  if (mon->fd == -1) {
    XLOG_ERROR("open(%s):%s", dev_node, strerror(errno));
    return NULL;
  }

  XLOG_INFO("opened %s (fd:%d)", dev_node, mon->fd);

  int ret = ioctl(mon->fd,HIDIOCGRAWINFO, &mon->info);
  if (ret < 0) {
    XLOG_ERROR("failed to get device info. %s", strerror(errno));
    return NULL;
  }

  ret = ioctl(mon->fd, HIDIOCGRDESCSIZE, &mon->desc.size);
  if (ret < 0) {
    XLOG_ERROR("failed to get descriptor size. %s", strerror(errno));
    return NULL;
  }

  ret = ioctl(mon->fd, HIDIOCGRDESC, &mon->desc);
  if (ret < 0) {
    XLOG_ERROR("failed to get descriptor. %s", strerror(errno));
    return NULL;
  }

  ret = ioctl(mon->fd, HIDIOCGRAWNAME(255), mon->name);
  if (ret < 0) {
    XLOG_ERROR("failed to get name. %s", strerror(errno));
    return NULL;
  }

  XLOG_INFO("bus_type: %s", hidp_bus_to_string(mon->info.bustype));
  XLOG_INFO("vendor  : 0x%04hx", mon->info.vendor);
  XLOG_INFO("product : 0x%04hx", mon->info.product);
  XLOG_INFO("name    : %s", mon->name);
  XLOG_INFO(" --- end new HID device ---");

  mon->next = list;

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

void client_send_create(ConnectedClient *clnt, HIDRawMonitor *mon)
{
  if (!clnt)
    return;

   // amount of data about to be sent
  // 2 bytes size of packet
  // 2 bytes PacketType
  // 2 bytes uhid_event_type
  // x bytes payload
  int16_t packet_size = (int16_t) (8 + sizeof(struct uhid_create2_req));
  int16_t packet_type = (int16_t) (PacketTypeCreate);
  int16_t event_type = (int16_t) UHID_CREATE2;

  XLOG_INFO("packet_size:%d", packet_size);
  XLOG_INFO("sizeof(uhid_create2_req):%d", (int) sizeof(struct uhid_create2_req));

  packet_size = htole16(packet_size);
  packet_type = htole16(packet_type);
  event_type = htole16(event_type);
  int16_t device_id = htole16(mon->device_id);

  struct uhid_create2_req req;
  memset(&req, 0, sizeof(req));
  strncpy(req.name, mon->name, sizeof(req.name));
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
  iov[1].iov_base = &device_id;
  iov[1].iov_len = sizeof(device_id);
  iov[2].iov_base = &packet_type;
  iov[2].iov_len = sizeof(packet_type);
  iov[3].iov_base = &event_type;
  iov[3].iov_len = sizeof(event_type);
  iov[4].iov_base = &req;
  iov[4].iov_len = sizeof(req);

  ssize_t bytes_written = writev(clnt->fd, iov, 5);
  if (bytes_written < 0)
    XLOG_ERROR("writev:%s", strerror(errno));
  // else
  //  XLOG_INFO("writev:%d", (int) bytes_written);
}

void client_send_delete(ConnectedClient *clnt, HIDRawMonitor *mon)
{
  if (!clnt)
    return;

  HIDCommandPacketHeader pkt;
  pkt.packet_size = sizeof(HIDCommandPacketHeader);
  pkt.device_id = mon->device_id;
  pkt.packet_type = PacketTypeDelete;
  pkt.event_type = UHID_DESTROY;
  hid_command_packet_header_to_network(&pkt);

  struct iovec iov[4];
  iov[0].iov_base = &pkt.packet_size;
  iov[0].iov_len = sizeof(pkt.packet_size);
  iov[1].iov_base = &pkt.device_id;
  iov[1].iov_len = sizeof(pkt.device_id);
  iov[2].iov_base = &pkt.packet_type;
  iov[2].iov_len = sizeof(pkt.packet_type);
  iov[3].iov_base = &pkt.event_type;
  iov[3].iov_len = sizeof(pkt.event_type);

  ssize_t bytes_written = writev(clnt->fd, iov, 4);
  if (bytes_written < 0) {
    int err = errno;
    XLOG_WARN("error sending UHID_DESTROY. %s", strerror(err));
  }
}

void hidp_push_fd(fd_set *set, int fd, int *max)
{
  FD_SET(fd, set);
  if (fd > *max)
    *max = fd;
  // XLOG_INFO("fd_set(%p, %d) - max:%d", set, fd, *max);
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

	char *saveptr = NULL;
	char *line;
	char *key;
	char *value;

	int found_id = 0;
	int found_serial = 0;
	int found_name = 0;

	line = strtok_r(tmp, "\n", &saveptr);
	while (line != NULL) {
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
		line = strtok_r(NULL, "\n", &saveptr);
	}

	return (found_id && found_name && found_serial);
}

HIDRawMonitor *hidraw_monitor_new(struct udev *udev)
{
  HIDRawMonitor *mon = NULL;
  XLOG_INFO("creating HIDRAW monitor");

  struct udev_enumerate *e = udev_enumerate_new(udev);
  udev_enumerate_add_match_subsystem(e, "hidraw");
  udev_enumerate_scan_devices(e);

  struct udev_list_entry *devices = udev_enumerate_get_list_entry(e);

  XLOG_INFO("scanning for any existing HIDs");
  for (struct udev_list_entry *itr = devices; itr; itr = udev_list_entry_get_next(itr)) {
    const char *sysfs_path = udev_list_entry_get_name(itr);
    struct udev_device *raw_dev = udev_device_new_from_syspath(udev, sysfs_path);
    if (raw_dev) {
      mon = hidraw_monitor_from_udev(mon, raw_dev);
      udev_device_unref(raw_dev);
    }
  }
  udev_enumerate_unref(e);
  XLOG_INFO("new HID scan complete");

  return mon;
}

HIDMonitorServer *hid_monitor_server_new(const char *listen_addr, int listen_port)
{
  HIDMonitorServer *server = calloc(1, sizeof(HIDMonitorServer));

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
    return NULL;
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
    return NULL;
  }

  ret = listen(server->listen_fd, 1);
  if (ret == -1) {
    close(server->listen_fd);
    XLOG_ERROR("listen:%s", strerror(errno));
    return NULL;
  }

  server->udev = udev_new();
  server->mon = udev_monitor_new_from_netlink(server->udev, "udev");
  udev_monitor_filter_add_match_subsystem_devtype(server->mon, "hidraw", NULL);
  udev_monitor_enable_receiving(server->mon);
  server->monitor_fd = udev_monitor_get_fd(server->mon);
  server->locally_active_hid_devices = hidraw_monitor_new(server->udev);

  XLOG_INFO("server creation completed");

  return server;
}

void hid_monitor_server_accept(HIDMonitorServer *server)
{
  if (server->client) {
    if (server->client->fd != -1)
      close(server->client->fd);
  }
  else {
    server->client = calloc(1, sizeof(ConnectedClient));
    server->client->fd = -1;
    server->client->remote_endpoint_size = sizeof(struct sockaddr_in);
  }

  server->client->fd = accept(server->listen_fd, (struct sockaddr *) &server->client->remote_endpoint,
    &server->client->remote_endpoint_size);
  if (server->client->fd  == -1) {
    XLOG_WARN("error accepting new client connection. %s", strerror(errno));
    return;
  }

  for (HIDRawMonitor *dev = server->locally_active_hid_devices; dev; dev = dev->next) {
    client_send_create(server->client, dev);
  }
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
    client_send_create(server->client,
      hidraw_monitor_from_udev(server->locally_active_hid_devices, dev));
  }
  else if (strcasecmp(action, "remove") == 0) {
    XLOG_INFO("remove:%s", udev_device_get_devnode(dev));
    for (HIDRawMonitor *mon = server->locally_active_hid_devices; mon; mon = mon->next) {
      const char *devnode = udev_device_get_devnode(mon->raw_dev);
      if (strcmp(devnode, udev_device_get_devnode(dev)) == 0) {
        client_send_delete(server->client, mon);
        server->locally_active_hid_devices = hidraw_monitor_free_node(server->locally_active_hid_devices, mon);
        break;
      }
    }
  }

  udev_device_unref(dev);
}

void hidraw_monitor_free(HIDRawMonitor *hidraw)
{
  if (hidraw->raw_dev)
    udev_device_unref(hidraw->raw_dev);

  if (hidraw->fd > 0)
    close(hidraw->fd);

  free(hidraw);
}

HIDRawMonitor *hidraw_monitor_free_node(HIDRawMonitor *list, HIDRawMonitor *node)
{
  if  (!list)
    return NULL;

  HIDRawMonitor *prev = NULL;
  HIDRawMonitor *curr = list;

  while (curr && curr != node) {
    prev = curr;
    curr = curr->next;
  }

  if (!prev && curr) {
    list = list->next;
    hidraw_monitor_free(curr);
    return list;
  }
  else if (prev && curr) {
    prev->next = curr->next;
    hidraw_monitor_free(curr);
  }

  return list;
}
