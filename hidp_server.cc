#include "hidp_common.h"
#include "hidp_device.h"
#include "hidp_net.h"
#include "hidp_proto.h"

#include <memory>

#include <errno.h>
#include <string.h>
#include <sys/select.h>

int main(int argc, char *argv[])
{
  InputDeviceMonitor device_monitor;

  TcpListener tcp_listener("10.0.0.133", 10020);
  tcp_listener.Start();

  std::unique_ptr<Socket> client;
  std::vector< std::unique_ptr<InputDevice> > input_devices = device_monitor.FindAll();

  while (true) {
    fd_set read_fds;
    FD_ZERO(&read_fds);

    int max_fd = -1;
    fd_set_add(read_fds, tcp_listener, &max_fd);
    fd_set_add(read_fds, device_monitor, &max_fd);
    for (const std::unique_ptr<InputDevice> &dev : input_devices)
      fd_set_add(read_fds, dev, &max_fd);
    if (client)
      fd_set_add(read_fds, client, &max_fd);

    int ret = select(max_fd + 1,  &read_fds, nullptr, nullptr, nullptr);
    if (ret == -1) {
      XLOG_INFO("select returned error. %s", strerror(errno));
      continue;
    }

    if (fd_is_set(read_fds, tcp_listener)) {
      client = tcp_listener.Accept();
      ProtocolWriter writer(*client);
      for (const std::unique_ptr<InputDevice> &dev : input_devices)
        writer.SendCreate(dev);
    }

    if (client && fd_is_set(read_fds, client)) {
      ProtocolReader reader(*client);
      reader.ProcessIncomingClientMessage(input_devices);
    }
    
    if (fd_is_set(read_fds, device_monitor)) {
      device_monitor.ReadNext(
        [&input_devices, &client](std::unique_ptr<InputDevice> new_device) {
          if (client) {
            ProtocolWriter writer(*client);
            writer.SendCreate(new_device);
          }
          input_devices.push_back(std::move(new_device));
        },
        // device disconnected
        [&input_devices, &client](std::string uuid) {
          XLOG_INFO("device disconnected");
          auto old_device = std::find_if(std::begin(input_devices), std::end(input_devices),
            [&uuid](const std::unique_ptr<InputDevice>& dev)
            {
              return dev->GetId() == uuid;
            });
          if (old_device != std::end(input_devices)) {
            if (client) {
              ProtocolWriter writer(*client);
              writer.SendDelete(*old_device);
            }
            input_devices.erase(old_device);
          }
        });
    }

    for (std::unique_ptr<InputDevice> &dev : input_devices) {
      if (fd_is_set(read_fds, dev)) {
        dev->ReadInputReport();
        if (client) {
          ProtocolWriter writer(*client);
          writer.SendInputReport(dev);
        }
      }
    }
  }
}
