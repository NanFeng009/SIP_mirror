#include <unistd.h>
#include <time.h>

#include "phonetime.h"

/********************** Clock variables ***********************/

unsigned long clock_tick = 0;


// Returns the number of microseconds that have passed since SIPp
// started. Also updates the current clock_tick.
unsigned long long getmicroseconds()
{
    struct timespec time;
    unsigned long long microseconds;
    LOCAL unsigned long long start_time = 0;



    clock_gettime(CLOCK_MONOTONIC, &time);

    microseconds = (MICROSECONDS_PER_SECOND * time.tv_sec) + (time.tv_nsec / NANOSECONDS_PER_MICROSECOND);
    if (start_time == 0) {
        start_time = microseconds - 1;
    }
    microseconds = microseconds - start_time;

    // Static global from sipp.hpp
    clock_tick = microseconds / MICROSECONDS_PER_MILLISECOND;

    return microseconds;
}

// Returns the number of milliseconds that have passed since SIPp
// started. Also updates the current clock_tick.
unsigned long getmilliseconds()
{
    return getmicroseconds() / MICROSECONDS_PER_MILLISECOND;
}

// Sleeps for the given number of microseconds. Avoids the potential
// EINVAL when using usleep() to sleep for a second or more.
void sipp_usleep(unsigned long usec)
{
    if (usec >= 1000000) {
        sleep(usec / 1000000);
    }
    usec %= 1000000;
    usleep(usec);
}

/*
long computeDiffTimeInMs(struct timeval* tf, struct timeval* ti)
{
    long v1, v2;

    v1 = tf->tv_sec - ti->tv_sec;
    v2 = tf->tv_usec - ti->tv_usec;
    if (v2 < 0) v2 += 1000000, v1--;
    return (v1*1000 + v2/1000);
}
*/
