#include "hidp_device.h"
#include "hidp_net.h"
#include "hidp_proto.h"

#include <libudev.h>
#include <sys/select.h>
#include <stdio.h>
#include <memory>

int main(int argc, char *argv[])
{
  InputDeviceMonitor device_monitor;

  TcpListener tcp_listener("127.0.0.1", 10020);
  tcp_listener.Start();

  std::unique_ptr<Socket> client;
  std::vector< std::unique_ptr<InputDevice> > input_devices;

  while (true) {
    fd_set read_fds;
    FD_ZERO(&read_fds);

    int max_fd = -1;
    fd_set_add(read_fds, tcp_listener, &max_fd);
    fd_set_add(read_fds, device_monitor, &max_fd);
    for (const std::unique_ptr<InputDevice> &dev : input_devices)
      fd_set_add(read_fds, *dev, &max_fd);
    if (client)
      fd_set_add(read_fds, *client, &max_fd);

    int ret = select(max_fd + 1,  &read_fds, nullptr, nullptr, nullptr);
    if (ret == -1) {
      // TODO
    }

    if (client && fd_is_set(read_fds, *client)) {
      // TODO: read incoming message from client
      ProtocolReader reader(*client);
      reader.ProcessIncomingClientMessage();
    }

    if (fd_is_set(read_fds, tcp_listener))
      client = tcp_listener.Accept();
    
    if (fd_is_set(read_fds, device_monitor)) {
      device_monitor.ReadNext(
        // device connected
        [&input_devices, &client](std::unique_ptr<InputDevice> new_device) {
          ProtocolWriter writer(*client);
          writer.SendCreate(new_device);
          input_devices.push_back(std::move(new_device));
        },
        // device disconnected
        [&input_devices, &client](std::string uuid) {
          auto old_device = std::find_if(std::begin(input_devices), std::end(input_devices),
            [&uuid](const std::unique_ptr<InputDevice>& dev)
            {
              return dev->Id() == uuid;
            });
          if (old_device != std::end(input_devices)) {
            ProtocolWriter writer(*client);
            writer.SendDelete(*old_device);
            input_devices.erase(old_device);
          }
        });
    }

    for (std::unique_ptr<InputDevice> &dev : input_devices) {
      if (fd_is_set(read_fds, *dev)) {
        dev->ReadInputReport();
        ProtocolWriter writer(*client);
        writer.SendInputReport(dev);
      }
    }
  }
}
