cmake_minimum_required(VERSION 3.16)
project(HIDProjector)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBEVDEV REQUIRED libevdev)
pkg_check_modules(LIBUDEV REQUIRED libudev)

add_executable(hidpservd server.c common.c)
target_include_directories(hidpservd PUBLIC ${LIBUDEV_INCLUDE_DIRS})
target_link_libraries(hidpservd ${LIBUDEV_LIBRARIES})
