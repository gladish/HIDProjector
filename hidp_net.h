#pragma once

#include <memory>
#include <string>
#include <sys/socket.h>

class Socket;
class TcpClient;
class TcpListener;

class Socket {
  friend class TcpListener;
public:
  Socket();
  ~Socket();
  int Read(void *buff, int count);
  int Write(const void* buff, int count);
  void Bind(const char *addr, int port);
  void Connect(const char *addr, int port);
  void Close();
  inline int Descriptor() const;
  inline bool IsConnected() const;
private:
  Socket(int fd) 
    : m_fd(fd) { }
  void SetRemoteEndpoint(const sockaddr_storage &remote, socklen_t length);
  void SetLocalEndpoint(const sockaddr_storage &remote, socklen_t length);
private:
  int               m_fd;
  sockaddr_storage  m_remote_endpoint;
  socklen_t         m_remote_endpoint_length;
  sockaddr_storage  m_local_endpoint;
  socklen_t         m_local_endpoint_length;
};

class TcpListener {
public:
  TcpListener(const char *addr, int port);
  void Start();
  std::unique_ptr<Socket> Accept();
  inline int Descriptor() const;
private:
  std::string       m_local_addr;
  int               m_local_port;
  Socket            m_socket;
};

class TcpClient {
public:
  inline int Read(void *buff, int count);
  inline int Write(const void* buff, int count);
  inline int Descriptor() const;
  inline Socket& GetSocket();
  void Connect(const char *addr, int port);
  inline bool IsConnected() const;
private:
  Socket            m_socket;
  bool              m_connected;
};

inline Socket& TcpClient::GetSocket()
{
  return m_socket;
}

inline int TcpClient::Read(void *buff, int count)
{
  return m_socket.Read(buff, count);
}

inline int TcpClient::Write(const void *buff, int count)
{
  return m_socket.Write(buff, count);
}

inline int TcpClient::Descriptor() const
{
  return m_socket.Descriptor();
}

inline int TcpListener::Descriptor() const
{
  return m_socket.Descriptor();
}

inline bool TcpClient::IsConnected() const
{
  return m_socket.IsConnected();
}

inline bool Socket::IsConnected() const
{
  return this->Descriptor() != -1;
}

inline int Socket::Descriptor() const
{
  return m_fd;
}

template<class T> const T& __ref(const T& obj) { return obj; }
template<class T> const T& __ref(const std::unique_ptr<T> &obj) { return *obj.get(); }

template<class T>
inline bool fd_is_set(fd_set& set, const T& carrier)
{
  return FD_ISSET(__ref(carrier).Descriptor(), &set);
}

template<class T>
void fd_set_add(fd_set& set, const T& carrier, int *max)
{
  int fd = __ref(carrier).Descriptor();
  FD_SET(fd, &set);
  if (fd > *max)
    *max = fd;
}
