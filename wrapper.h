#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/if_pflog.h>
#include <net/pfvar.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <errno.h>
#include <pcap.h>
#include <signal.h>

// From tcpdump/print-pflog.c
#ifndef NO_PID
#define NO_PID	(99999+1)
#endif
