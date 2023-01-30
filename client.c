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

#include "hidp.h"

typedef struct _VirtualHID VirtualHID;
struct _VirtualHID
{
  int16_t device_id;
  int     uhid_fd;
  VirtualHID *next;
};

typedef struct _HIDMonitorClient HIDMonitorClient;
struct _HIDMonitorClient
{
  int server_fd;
  socklen_t remote_endpoint_size;
  struct sockaddr_storage remote_endpoint;
  char read_buffer[sizeof(HIDCommandPacketHeader) + sizeof(struct uhid_event)];
  VirtualHID *vhids;
};

#define HID_COMMAND_PACKET(clnt) &(clnt->read_buffer[sizeof(HIDCommandPacketHeader)])
#define HID_COMMAND_HEADER(clnt) (HIDCommandPacketHeader *) &(clnt->read_buffer[0])

HIDMonitorClient *hid_monitor_client_new(const char *remote_addr, int remote_port);
int               hid_monitor_client_read(HIDMonitorClient *clnt);
void              hid_monitor_client_create(HIDMonitorClient *clnt);
void              hid_monitor_client_delete(HIDMonitorClient *clnt);
void              hid_monitor_client_submit_report(HIDMonitorClient *clnt);
VirtualHID       *hid_monitor_client_add_vhid(HIDMonitorClient *clnt, int16_t device_id);
VirtualHID       *hid_monitor_client_find_vhid(HIDMonitorClient *clnt, int16_t device_id);
VirtualHID       *hid_monitor_client_remove_vhid(HIDMonitorClient *clnt, int16_t device_id);
void              virtual_hid_free(VirtualHID *vhid);

int main(int argc, char *argv[])
{
  int ret;

  HIDMonitorClient *client = hid_monitor_client_new("10.0.0.133", 10020);
  if (!client)
    exit(1);

  while (true) {
    ret = hid_monitor_client_read(client);
    if (ret < 0) {
      XLOG_ERROR("failed to read");
      exit(1);
    }

    HIDCommandPacketHeader *pkt = (HIDCommandPacketHeader *) &client->read_buffer[0];
    switch (pkt->packet_type) {
      case PacketTypeCreate:
      hid_monitor_client_create(client);
      break;

      case PacketTypeDelete:
      hid_monitor_client_delete(client);
      break;

      case PacketTypeReport:
      hid_monitor_client_submit_report(client);
      break;
    }
  }

  #if 0
  while (true) {
    memset(buff, 0, sizeof(buff));

    ssize_t bytes_read = recv(soc, &buff[0], 2, 0);
    pkt->packet_size = le16toh(pkt->packet_size);
    if (bytes_read == 0)
      break;

    // read first 2 bytes (packet_size)
    pkt->packet_size = le16toh(pkt->packet_size);
    XLOG_INFO("packet_size:%d", (int) pkt->packet_size);
    bytes_read = recv(soc,  &buff[2], (pkt->packet_size - 2), 0);
    if (bytes_read == 0)
      break;
    if (bytes_read == -1) {
      XLOG_ERROR("recv:%s", strerror(errno));
    }

    pkt->packet_type = le16toh(pkt->packet_type);
    pkt->event_type = le16toh(pkt->event_type);
    pkt->device_id = le16toh(pkt->device_id);

    XLOG_INFO("bytes_read:%d", (int) bytes_read);

    // XLOG_INFO("packet_size:%d", pkt->packet_size);
    // XLOG_INFO("packet_type:%d", pkt->packet_type);
    // XLOG_INFO("event_type :%d", pkt->event_type);
    // XLOG_INFO("device_id  :%d", pkt->device_id);
    switch (pkt->event_type) {
      case UHID_CREATE2:
      {
        struct uhid_create2_req *req = (struct uhid_create2_req *) pkt->data;
        struct uhid_event e;
        e.type = UHID_CREATE2;
        e.u.create2 = *req;
        XLOG_INFO("name   :%s", req->name);
        XLOG_INFO("vid    : %d", req->vendor);
        XLOG_INFO("pid    : %d", req->product);
        ssize_t ret = write(dev_uhid, &e, sizeof(e));
        if (ret == -1) {
          XLOG_INFO("write:%s", strerror(errno));
        }
        XLOG_INFO("write:%d", (int) ret);

      }
      break;
      case UHID_INPUT2:
      {
        struct uhid_input2_req *req = (struct uhid_input2_req *) pkt->data;
        req->size = le16toh(req->size);

        struct uhid_event e;
        e.type = UHID_INPUT2;
        e.u.input2 = *req;
        XLOG_INFO("size:%d", (int) e.u.input2.size);

        for (int i = 0; i < e.u.input2.size; ++i)
          printf("%02x ", e.u.input2.data[i]);
        printf("\n");

        ssize_t bytes_written = write(dev_uhid, &e, sizeof(e)); // e.u.input2.size);
        if (ret == -1)
          XLOG_ERROR("write:%s", strerror(errno));
        else
          XLOG_INFO("write:%d", (int) bytes_written);

      }
      break;
      default:
        break;
    }
  }

  close(soc);
  #endif

  return 0;
}

HIDMonitorClient *hid_monitor_client_new(const char *remote_addr, int remote_port)
{
  HIDMonitorClient *client = calloc(1, sizeof(HIDMonitorClient));
  client->server_fd = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in *v4 = (struct sockaddr_in *) &client->remote_endpoint;

  int ret = inet_pton(AF_INET, remote_addr, &v4->sin_addr);
  if (ret == -1)
    XLOG_FATAL("inet_pton:%s", strerror(errno));

  v4->sin_port = htons(remote_port);
  v4->sin_family = AF_INET;
  client->remote_endpoint_size = sizeof(struct sockaddr_in);

  ret = connect(client->server_fd, (const struct sockaddr *) &client->remote_endpoint, client->remote_endpoint_size);
  if (ret == -1)
    XLOG_FATAL("connect:%s", strerror(errno));

  return client;
}

int hid_monitor_client_read(HIDMonitorClient *clnt)
{
  memset(clnt->read_buffer, 0, sizeof(clnt->read_buffer));

  const int sizeof_header = (int) sizeof(HIDCommandPacketHeader);

  HIDCommandPacketHeader *header = (HIDCommandPacketHeader *) &clnt->read_buffer[0];

  int bytes_read = hidp_read_until(clnt->server_fd, &clnt->read_buffer[0], sizeof_header);
  if (bytes_read < 0) {
    XLOG_ERROR("error reading packet header:%s", strerror(-bytes_read));
    return bytes_read;
  }

  hid_command_packet_header_from_network(header);

  // read remainder of packet
  bytes_read = hidp_read_until(clnt->server_fd, &clnt->read_buffer[sizeof_header],
    (header->packet_size - sizeof_header));
  if (bytes_read < 0) {
    XLOG_ERROR("error reading packet body. %s", strerror(-bytes_read));
    return -bytes_read;
  }

  return 0;
}


void hid_monitor_client_create(HIDMonitorClient *clnt)
{
  XLOG_INFO("creating new VHID");

  struct uhid_create2_req *req = (struct uhid_create2_req *) HID_COMMAND_PACKET(clnt);

  HIDCommandPacketHeader *header = HID_COMMAND_HEADER(clnt);
  VirtualHID *vhid = hid_monitor_client_add_vhid(clnt, header->device_id);

  struct uhid_event e;
  e.type = UHID_CREATE2;
  e.u.create2 = *req;

  ssize_t bytes_written = write(vhid->uhid_fd, &e, sizeof(e));
  if (bytes_written == -1) {
    XLOG_ERROR("create new VHID failed to write to uhid device. %s", strerror(errno));
    return;
  }

  XLOG_INFO("created new VHID for %s", e.u.create2.name);
}

void hid_monitor_client_delete(HIDMonitorClient *clnt)
{
  XLOG_INFO("removing existing VHID");

  HIDCommandPacketHeader *header = HID_COMMAND_HEADER(clnt);

  VirtualHID *vhid = hid_monitor_client_find_vhid(clnt, header->device_id);
  if (!vhid) {
    XLOG_WARN("failed to find VHID with id:%d", header->device_id);
    return;
  }

  struct uhid_event e;
  e.type = UHID_DESTROY;

  ssize_t bytes_written = write(vhid->uhid_fd, &e, sizeof(e));
  if (bytes_written == -1) {
    XLOG_INFO("failed to send UHID_DELETE. %s", strerror(errno));
  }

  clnt->vhids = hid_monitor_client_remove_vhid(clnt, vhid->device_id);
}

void hid_monitor_client_submit_report(HIDMonitorClient *clnt)
{
  struct uhid_input2_req *req = (struct uhid_input2_req *) HID_COMMAND_PACKET(clnt);

  HIDCommandPacketHeader *header = HID_COMMAND_HEADER(clnt);
  VirtualHID *vhid = hid_monitor_client_find_vhid(clnt, header->device_id);
  if (!vhid) {
    XLOG_WARN("failed to find VHID with id:%d", header->device_id);
    return;
  }

  struct uhid_event e;
  e.type = UHID_INPUT2;
  e.u.input2 = *req;

  ssize_t bytes_written = write(vhid->uhid_fd, &e, sizeof(e));
  if (bytes_written == 0) {
    XLOG_INFO("socket closed");
  }

  if (bytes_written == -1) {
    XLOG_WARN("failed to write input report. %s", strerror(errno));
  }
}

VirtualHID *hid_monitor_client_add_vhid(HIDMonitorClient *clnt, int16_t device_id)
{
  VirtualHID *vhid = calloc(1, sizeof(VirtualHID));
  vhid->device_id = device_id;
  vhid->uhid_fd = open("/dev/uhid",  O_RDWR | O_CLOEXEC);
  vhid->next = clnt->vhids;
  clnt->vhids = vhid;
  XLOG_INFO("create new VHID device_id:%d uhid_fd:%d", device_id, vhid->uhid_fd);
  return vhid;
}

VirtualHID  *hid_monitor_client_find_vhid(HIDMonitorClient *clnt, int16_t device_id)
{
  VirtualHID *i;
  for (i = clnt->vhids; i; i = i->next) {
    if (i->device_id == device_id)
      return i;
  }
  return  NULL;
}

void virtual_hid_free(VirtualHID *vhid)
{
  if (!vhid)
    return;
  if (vhid->uhid_fd > 0)
    close(vhid->uhid_fd);
  free(vhid);
}

VirtualHID *hid_monitor_client_remove_vhid(HIDMonitorClient *clnt, int16_t device_id)
{
  VirtualHID *prev = NULL;
  VirtualHID *curr = clnt->vhids;

  while (curr && curr->device_id != device_id) {
    prev = curr;
    curr = curr->next;
  }

  if  (!prev && curr) {
    clnt->vhids = clnt->vhids->next;
    virtual_hid_free(curr);
    return clnt->vhids;
  }
  else if (prev && curr) {
    prev->next= curr->next;
    virtual_hid_free(curr);
  }

  return clnt->vhids;
}
