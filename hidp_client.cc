#include "hidp_common.h"
#include "hidp_device.h"
#include "hidp_net.h"
#include "hidp_proto.h"

#include <chrono>
#include <thread>
#include <vector>

#include <errno.h>
#include <string.h>

int main(int argc, char *argv[])
{
  TcpClient client;

  std::vector< std::unique_ptr<InputDevice> > input_devices;

  while (true) {
    while (!client.IsConnected()) {
      try {
        client.Connect("10.0.0.133", 10020);
      }
      catch (const std::exception &err) {
        XLOG_INFO("errror connecting to server. %s", err.what());
      }
      if (!client.IsConnected()) {
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(1000ms);
      }
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);

    int max_fd = -1;
    fd_set_add(read_fds, client, &max_fd);
    for (std::unique_ptr<InputDevice> &dev : input_devices)
      fd_set_add(read_fds, dev, &max_fd);

    int ret = select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr);
    if (ret > 0) {
      if (fd_is_set(read_fds, client)) {
        ProtocolReader reader(client.GetSocket());
        reader.ProcessIncomingServerMessage(input_devices);
      }
      for (std::unique_ptr<InputDevice> &dev : input_devices) {
        if (fd_is_set(read_fds, *dev)) {
          ProtocolWriter writer(client.GetSocket());
          writer.SendGetReportRequest(dev);
        }
      }
    }
    else if (ret == -1) {
      XLOG_WARN("select returned an error. %s", strerror(errno));
    }
  }

  return 0;
}
