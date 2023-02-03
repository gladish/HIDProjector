#include "hidp_common.h"
#include "hidp_net.h"

#include <cstdarg>
#include <sstream>
#include <stdexcept>

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
  std::string AddressToString(sockaddr_storage &endpoint, int port)
  {
    char buff[128];
    inet_ntop(endpoint.ss_family, &endpoint, buff, sizeof(buff));
    std::stringstream address_string;
    address_string << buff;
    if (port != -1) {
      address_string << ":";
      address_string << port;
    }
    return address_string.str();
  }

  void ParseAddressAndPort(const char *addr, int port, sockaddr_storage &endpoint, socklen_t &length)
  {
    int ret;
    sockaddr_in *v4 = reinterpret_cast<sockaddr_in *>(&endpoint);

    ret = inet_pton(AF_INET, addr, &v4->sin_addr);
    if (ret == 1) {
      endpoint.ss_family = AF_INET;
      v4->sin_family = AF_INET;
      v4->sin_port = htons(port);
      length = sizeof(sockaddr_in);
      ret = 0;
    }
    else {
      sockaddr_in6 * v6 = reinterpret_cast<sockaddr_in6 *>(&endpoint);
      ret = inet_pton(AF_INET6, addr, &v6->sin6_addr);
      if (ret == 1) {
        endpoint.ss_family = AF_INET6;
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        length = sizeof(sockaddr_in6);
        ret = 0;
      }
    }

    if (ret)
      hidp_throw_errno(-EINVAL, "failed to parse address %s", addr);
  }
}

Socket::Socket()
{
  m_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (m_fd == -1)
    hidp_throw_errno(errno, "failed to create socket");
}

Socket::~Socket()
{
  if (m_fd != -1)
    close(m_fd);
}

TcpListener::TcpListener(const char *addr, int port)
  : m_local_addr(addr)
  , m_local_port(port)
{

}

void
TcpListener::Start()
{
  m_socket.Bind(m_local_addr.c_str(), m_local_port);

  int ret = listen(m_socket.Descriptor(), 2);
  if (ret == -1)
    hidp_throw_errno(errno, "failed to put socket in listen mode");
}

std::unique_ptr<Socket>
TcpListener::Accept()
{
  sockaddr_storage remote_endpoint;
  socklen_t remote_endpoint_length = sizeof(remote_endpoint);

  int fd = accept(m_socket.Descriptor(), reinterpret_cast<sockaddr *>(&remote_endpoint), &remote_endpoint_length);
  if (fd == -1)
    hidp_throw_errno(errno, "failed to accept incoming connection");

  std::string s = AddressToString(remote_endpoint, -1);
  XLOG_INFO("accepted new connection from %s", s.c_str());

  std::unique_ptr<Socket> soc{ new Socket(fd) };
  soc->SetRemoteEndpoint(remote_endpoint, remote_endpoint_length);
  return std::move(soc);
}

int Socket::Read(void *buff, int count)
{
  ssize_t bytes_read = 0;
  ssize_t bytes_to_read = count;
  while (bytes_read < bytes_to_read) {
    uint8_t *p = static_cast<uint8_t *>(buff);
    ssize_t n = recv(m_fd, p + bytes_read, (bytes_to_read - bytes_read), MSG_NOSIGNAL);
    if (n == 0) {
      Close();
      return -ENOTCONN;
    }
    if (n == -1) {
      int err = errno;
      Close();
      return -err;
    }
    bytes_read += n;
  }
  return static_cast<int>(bytes_read);
}

int Socket::Write(const void* buff, int count)
{
  ssize_t bytes_written = write(m_fd, buff, count);
  if (bytes_written <= 0) {
    close(m_fd);
    m_fd = -1;
    hidp_throw_errno(errno, "failed to write %d bytes", count);
  }
  return static_cast<int>(bytes_written);
}

void Socket::Close()
{
  if (m_fd != -1)
    close(m_fd);
  m_fd = -1;
}

void
Socket::Connect(const char *addr, int port)
{
  XLOG_INFO("attempting connection to %s:%d", addr, port);
  ParseAddressAndPort(addr, port, m_remote_endpoint, m_remote_endpoint_length);

  int ret = connect(m_fd, reinterpret_cast<const sockaddr *>(&m_remote_endpoint), m_remote_endpoint_length);
  if (ret == -1)
    hidp_throw_errno(errno, "filed to connect to %s:%d", addr, port);
}

void
Socket::Bind(const char *addr, int port)
{
  XLOG_INFO("binding interface to %s:%d", addr, port);
  ParseAddressAndPort(addr, port, m_local_endpoint, m_local_endpoint_length);

  int optval = 1;
  if (setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) < 0)
    hidp_throw_errno(m_fd, "failed to set REUSEADDR");

  int ret = ::bind(m_fd, reinterpret_cast<const sockaddr *>(&m_local_endpoint), m_local_endpoint_length);
  if (ret == -1)
    hidp_throw_errno(errno, "failed to bind to %s:%d", addr, port);
}

void Socket::SetRemoteEndpoint(const sockaddr_storage &remote, socklen_t length)
{
  m_remote_endpoint = remote;
  m_remote_endpoint_length = length;
}

void Socket::SetLocalEndpoint(const sockaddr_storage &local, socklen_t length)
{
  m_local_endpoint = local;
  m_local_endpoint_length = length;
}

void TcpClient::Connect(const char *addr, int port)
{
  m_socket.Connect(addr, port);
  m_connected = true;
}
