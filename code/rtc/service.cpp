#include <os>
#include <timers>
#include <ctime>
#include <rtc>

void Service::start()
{

  Timers::periodic(std::chrono::seconds(1), std::chrono::seconds(1),
  [] (uint64_t) {
    //printf("RTC::now %lu\n", RTC::now());
    //printf("RTC::boot_timestamp %lu\n", RTC::boot_timestamp());
    printf("RTC::nanos_now %lu\n", RTC::nanos_now());
    printf("OS::nanos_since_boot %lu\n\n", OS::nanos_since_boot());
    //printf("arch_wall_clock().tv_sec %lu\n", __arch_wall_clock().tv_sec);
    //printf("arch_wall_clock().tv_nsec %lu\n", __arch_wall_clock().tv_nsec);
    //printf("ctime %lu\n", time(0));
  });
}
