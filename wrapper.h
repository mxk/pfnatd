#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/if_pflog.h>
#include <net/pfvar.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <pcap.h>

#ifndef NO_PID
#define NO_PID	(99999+1)
#endif
