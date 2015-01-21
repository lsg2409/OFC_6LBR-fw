#include "contiki-net.h"
#include "ip64.h"
#include "ip64-addr.h"
#include "ip64-addrmap.h"
#include "uip-debug.h"

#include <string.h> /* for memcpy() */
#include <stdio.h> /* for printf() */

#define EPHEMERAL_PORTRANGE     1024

#define IPV6_HDRLEN             40
#define IPV4_HDRLEN             20

#define IP_PROTO_ICMPV4         1
#define IP_PROTO_TCP            6
#define IP_PROTO_UDP            17
#define IP_PROTO_ICMPV6         58

#define ICMP_ECHO_REPLY         0
#define ICMP_ECHO               8
#define ICMP6_ECHO_REPLY        129
#define ICMP6_ECHO              128
#define BUFSIZE                 UIP_BUFSIZE
/*---------------------------------------------------------------------------*/
uip_buf_t ip64_packet_buffer_aligned;
static uip_ip4addr_t ip64_hostaddr;
static uip_ip4addr_t ip64_netmask;
static uip_ip4addr_t ip64_draddr;
static uint16_t ipid;
static uip_ip6addr_t ipv6_local_address;
static uint8_t ip64_hostaddr_configured = 0;
static uint8_t ipv6_local_address_configured = 0;
/*---------------------------------------------------------------------------*/
#define ip64_buffer               (ip64_packet_buffer_aligned.u8)
#define UIP_IP_BUF                ((struct ipv6_hdr *)&uip_buf[UIP_LLH_LEN])
#define IP64_IP_BUF               ((struct ipv4_hdr *)&ip64_buffer[UIP_LLH_LEN])
#define UIP_ICMP_BUF              ((struct icmpv6_hdr *)&uip_buf[IPV6_HDRLEN])
#define IP64_ICMP_BUF             ((struct icmpv4_hdr *)&ip64_buffer[IPV4_HDRLEN])
#define UIP_UDP_BUF               ((struct udp_hdr *)&uip_buf[IPV6_HDRLEN])
#define UIP_TCP_BUF               ((struct tcp_hdr *)&uip_buf[IPV6_HDRLEN])

#define DEBUG 0
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */
/*---------------------------------------------------------------------------*/
PROCESS_NAME(router_arp_process);
/*---------------------------------------------------------------------------*/void
ip64_ipv4_addr_init(void)
{
  uip_ip4addr_t ipv4addr;

  uip_ipaddr(&ipv4addr, 192,168,1,99);
  ip64_set_hostaddr(&ipv4addr);
  
  uip_ipaddr(&ipv4addr, 255,255,255,0);
  ip64_set_netmask(&ipv4addr);
  
  uip_ipaddr(&ipv4addr, 192,168,1,1);
  ip64_set_draddr(&ipv4addr);
}
/*---------------------------------------------------------------------------*/
void
ip64_init(void)
{
  int i;
  uint8_t state;

  ip64_hostaddr_configured = 0;

  PRINTF("ip64_init\n");
  ip64_addrmap_init();
  
#if IP64_CONF_DHCP
  ip64_ipv4_dhcp_init();
#else
  /* @mcroal:DHCP is bad, use manual ipv4 address configue */
  ip64_ipv4_addr_init();
#endif /* IP64_CONF_DHCP */
  process_start(&router_arp_process, NULL);
  /* Specify an IPv6 address for local communication to the
     host. We'll just pick the first one we find in our list. */
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    PRINTF("i %d used %d\n", i, uip_ds6_if.addr_list[i].isused);
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      ip64_set_ipv6_address(&uip_ds6_if.addr_list[i].ipaddr);
      break;
    }
  }
}
/*---------------------------------------------------------------------------*/
void
ip64_set_hostaddr(const uip_ip4addr_t *hostaddr)
{
  ip64_hostaddr_configured = 1;
  ip64_addr_copy4(&ip64_hostaddr, hostaddr);
}
/*---------------------------------------------------------------------------*/
void
ip64_set_netmask(const uip_ip4addr_t *netmask)
{
  ip64_addr_copy4(&ip64_netmask, netmask);
}
/*---------------------------------------------------------------------------*/
void
ip64_set_draddr(const uip_ip4addr_t *draddr)
{
  ip64_addr_copy4(&ip64_draddr, draddr);
}
/*---------------------------------------------------------------------------*/
const uip_ip4addr_t *
ip64_get_hostaddr(void)
{
  return &ip64_hostaddr;
}
/*---------------------------------------------------------------------------*/
const uip_ip4addr_t *
ip64_get_netmask(void)
{
  return &ip64_netmask;
}
/*---------------------------------------------------------------------------*/
const uip_ip4addr_t *
ip64_get_draddr(void)
{
  return &ip64_draddr;
}
/*---------------------------------------------------------------------------*/
void
ip64_set_ipv4_address(const uip_ip4addr_t *addr, const uip_ip4addr_t *netmask)
{
  ip64_set_hostaddr(addr);
  ip64_set_netmask(netmask);

  PRINTF("ip64_set_ipv4_address: configuring address %d.%d.%d.%d/%d.%d.%d.%d\n",
	 ip64_hostaddr.u8[0], ip64_hostaddr.u8[1],
	 ip64_hostaddr.u8[2], ip64_hostaddr.u8[3],
	 ip64_netmask.u8[0], ip64_netmask.u8[1],
	 ip64_netmask.u8[2], ip64_netmask.u8[3]);
}
/*---------------------------------------------------------------------------*/
void
ip64_set_ipv6_address(const uip_ip6addr_t *addr)
{
  ip64_addr_copy6(&ipv6_local_address, (const uip_ip6addr_t *)addr);
  ipv6_local_address_configured = 1;

  PRINTF("ip64_set_ipv6_address: configuring address ");
//  uip_debug_ipaddr_print(addr);
  PRINTF("\n");
}
/*---------------------------------------------------------------------------*/
static uint16_t
chksum(uint16_t sum, const uint8_t *data, uint16_t len)
{
  uint16_t t;
  const uint8_t *dataptr;
  const uint8_t *last_byte;

  dataptr = data;
  last_byte = data + len - 1;

  while(dataptr < last_byte) {	/* At least two more bytes */
    t = (dataptr[0] << 8) + dataptr[1];
    sum += t;
    if(sum < t) {
      sum++;		/* carry */
    }
    dataptr += 2;
  }

  if(dataptr == last_byte) {
    t = (dataptr[0] << 8) + 0;
    sum += t;
    if(sum < t) {
      sum++;		/* carry */
    }
  }

  /* Return sum in host byte order. */
  return sum;
}
/*---------------------------------------------------------------------------*/
static uint16_t
ipv4_checksum(struct ipv4_hdr *hdr)
{
  uint16_t sum;

  sum = chksum(0, (uint8_t *)hdr, IPV4_HDRLEN);
  return (sum == 0) ? 0xffff : uip_htons(sum);
}
/*---------------------------------------------------------------------------*/
static uint16_t
ipv4_transport_checksum(uint8_t *packet, uint16_t len, uint8_t proto)
{
  uint16_t transport_layer_len;
  uint16_t sum;
  struct ipv4_hdr *v4hdr = (struct ipv4_hdr *)packet;

  transport_layer_len = len - IPV4_HDRLEN;

  /* First sum pseudoheader. */

  if(proto != IP_PROTO_ICMPV4) {
    /* IP protocol and length fields. This addition cannot carry. */
    sum = transport_layer_len + proto;
    /* Sum IP source and destination addresses. */
    sum = chksum(sum, (uint8_t *)&v4hdr->srcipaddr, 2 * sizeof(uip_ip4addr_t));
  } else {
    /* ping replies' checksums are calculated over the icmp-part only */
    sum = 0;
  }

  /* Sum transport layer header and data. */
  sum = chksum(sum, &packet[IPV4_HDRLEN], transport_layer_len);

  return (sum == 0) ? 0xffff : uip_htons(sum);
}
/*---------------------------------------------------------------------------*/
static uint16_t
ipv6_transport_checksum(uint8_t *packet, uint16_t len, uint8_t proto)
{
  uint16_t transport_layer_len;
  uint16_t sum;
  struct ipv6_hdr *v6hdr = (struct ipv6_hdr *)packet;

  transport_layer_len = len - IPV6_HDRLEN;

  /* First sum pseudoheader. */

  /* IP protocol and length fields. This addition cannot carry. */
  sum = transport_layer_len + proto;
  /* Sum IP source and destination addresses. */
  sum = chksum(sum, (uint8_t *)&v6hdr->srcipaddr, sizeof(uip_ip6addr_t));
  sum = chksum(sum, (uint8_t *)&v6hdr->destipaddr, sizeof(uip_ip6addr_t));

  /* Sum transport layer header and data. */
  sum = chksum(sum, &packet[IPV6_HDRLEN], transport_layer_len);

  return (sum == 0) ? 0xffff : uip_htons(sum);
}
/*---------------------------------------------------------------------------*/
uint16_t
ip64_6to4(void)
{
  uint16_t ipv6len, ipv4len;
  struct ip64_addrmap_entry *m;

  if((UIP_IP_BUF->len[0] << 8) + UIP_IP_BUF->len[1] <= uip_len) {
    ipv6len = (UIP_IP_BUF->len[0] << 8) + UIP_IP_BUF->len[1] + IPV6_HDRLEN;
  } else {
    return 0;
  }

  /* We copy the data from the IPv6 packet into the IPv4 packet. We do
     not modify the data in any way. */
   memcpy(&ip64_buffer[IPV4_HDRLEN],
	 &uip_buf[IPV6_HDRLEN],
	 ipv6len - IPV6_HDRLEN);

  /* Translate the IPv6 header into an IPv4 header. */

  /* First the basics: the IPv4 version, header length, type of
     service, and offset fields. Those are the same for all IPv4
     packets we send, regardless of the values found in the IPv6
     packet. */
  IP64_IP_BUF->vhl = 0x45;
  IP64_IP_BUF->tos = 0;
  IP64_IP_BUF->ipoffset[0] = IP64_IP_BUF->ipoffset[1] = 0;

  /* We assume that the IPv6 packet has a fixed size header with no
     extension headers, and compute the length of the IPv4 packet and
     place the resulting value in the IPv4 packet header. */
  ipv4len = ipv6len - IPV6_HDRLEN + IPV4_HDRLEN;
  IP64_IP_BUF->len[0] = ipv4len >> 8;
  IP64_IP_BUF->len[1] = ipv4len & 0xff;

  /* For simplicity, we set a unique IP id for each outgoing IPv4
     packet. */
  ipid++;
  IP64_IP_BUF->ipid[0] = ipid >> 8;
  IP64_IP_BUF->ipid[1] = ipid & 0xff;

  /* Set the IPv4 protocol. We only support TCP, UDP, and ICMP at this
     point. While the IPv4 header protocol numbers are the same as the
     IPv6 next header numbers, the ICMPv4 and ICMPv6 numbers are
     different so we cannot simply copy the contents of the IPv6 next
     header field. */
  switch(UIP_IP_BUF->nxthdr) {
  case IP_PROTO_TCP:
    IP64_IP_BUF->proto = IP_PROTO_TCP;
    break;

  case IP_PROTO_UDP:
    IP64_IP_BUF->proto = IP_PROTO_UDP;
    break;

  case IP_PROTO_ICMPV6:
    IP64_IP_BUF->proto = IP_PROTO_ICMPV4;
    /* Translate only ECHO_REPLY messages. */
    if(UIP_ICMP_BUF->type == ICMP6_ECHO_REPLY) {
      IP64_ICMP_BUF->type = ICMP_ECHO_REPLY;
    } else {
      return 0;
    }
    break;

  default:
    /* We did not recognize the next header, and we do not attempt to
       translate something we do not understand, so we return 0 to
       indicate that no successful translation could be made. */
    return 0;
  }

  /* We set the IPv4 ttl value to the hoplim number from the IPv6
     header. This means that information about the IPv6 topology is
     transported into to the IPv4 network. */
  IP64_IP_BUF->ttl = UIP_IP_BUF->hoplim;

  /* We next convert the destination address. We make this conversion
     with the ip64_addr_6to4() function. If the conversion
     fails, ip64_addr_6to4() returns 0. If so, we also return 0 to
     indicate failure. */
  if(ip64_addr_6to4(&UIP_IP_BUF->destipaddr,
		    &IP64_IP_BUF->destipaddr) == 0) {
    return 0;
  }

  /* @mcroal:We set the source address in the IPv4 packet to be the IPv4
     address that we have been insert in a list of addrmap. */
  if((uip_ip6addr_cmp(&UIP_IP_BUF->srcipaddr, &ipv6_local_address))) {
    ip64_addr_copy4(&IP64_IP_BUF->srcipaddr, &ip64_hostaddr);
  } else {
    m = ip64_addrmap_lookup(&UIP_IP_BUF->srcipaddr, NULL);
    if(m == NULL) {	
        return 0;	    
    }
    /* @mcroal: ipv4 address confige success */
    ip64_addr_copy4(&IP64_IP_BUF->srcipaddr, &m->ip4addr);
  }
  
  
  /* The IPv4 header is now complete, so we can compute the IPv4
     header checksum. */
  IP64_IP_BUF->ipchksum = 0;
  IP64_IP_BUF->ipchksum = ~(ipv4_checksum(IP64_IP_BUF));

  /* The checksum is in different places in the different protocol
     headers, so we need to be sure that we update the correct
     field. */
  switch(IP64_IP_BUF->proto) {
  case IP_PROTO_TCP:
    UIP_TCP_BUF->tcpchksum = 0;
    UIP_TCP_BUF->tcpchksum = ~(ipv4_transport_checksum(ip64_buffer, ipv4len,
						  IP_PROTO_TCP));
    break;
  case IP_PROTO_UDP:
    UIP_UDP_BUF->udpchksum = 0;
    UIP_UDP_BUF->udpchksum = ~(ipv4_transport_checksum(ip64_buffer, ipv4len,
						  IP_PROTO_UDP));
    if(UIP_UDP_BUF->udpchksum == 0) {
      UIP_UDP_BUF->udpchksum = 0xffff;
    }
    break;
  case IP_PROTO_ICMPV4:
    IP64_ICMP_BUF->icmpchksum = 0;
    IP64_ICMP_BUF->icmpchksum = ~(ipv4_transport_checksum(ip64_buffer, ipv4len,
						      IP_PROTO_ICMPV4));
    break;

  default:
    return 0;
  }

  /* Finally, we return the length of the resulting IPv4 packet. */
  return ipv4len;
}
/*---------------------------------------------------------------------------*/
uint16_t
ip64_4to6(void)
{
  uint16_t ipv4len, ipv6len, ipv6_packet_len;
  struct ip64_addrmap_entry *m;

  if((IP64_IP_BUF->len[0] << 8) + IP64_IP_BUF->len[1] <= uip_len) {
    ipv4len = (IP64_IP_BUF->len[0] << 8) + IP64_IP_BUF->len[1];
  } else {
    return 0;
  }

  if(ipv4len <= IPV4_HDRLEN) {
    return 0;
  }

  /* Make sure that the resulting packet fits in the ip64 packet
     buffer. If not, we drop it. */
  if(ipv4len - IPV4_HDRLEN + IPV6_HDRLEN > BUFSIZE) {
    return 0;
  }
  /* We copy the data from the IPv4 packet into the IPv6 packet. */
  memcpy(&uip_buf[IPV6_HDRLEN],
	 &ip64_buffer[IPV4_HDRLEN],
	 ipv4len - IPV4_HDRLEN);

  ipv6len = ipv4len - IPV4_HDRLEN + IPV6_HDRLEN;
  ipv6_packet_len = ipv6len - IPV6_HDRLEN;

  /* Translate the IPv4 header into an IPv6 header. */

  /* We first fill in the simple fields: IP header version, traffic
     class and flow label, and length fields. */
  UIP_IP_BUF->vtc = 0x60;
  UIP_IP_BUF->tcflow = 0;
  UIP_IP_BUF->flow = 0;
  UIP_IP_BUF->len[0] = ipv6_packet_len >> 8;
  UIP_IP_BUF->len[1] = ipv6_packet_len & 0xff;

  /* We use the IPv4 TTL field as the IPv6 hop limit field. */
  UIP_IP_BUF->hoplim = IP64_IP_BUF->ttl;

  
  /* We now translate the IPv4 source and destination addresses to
     IPv6 source and destination addresses. We translate the IPv4
     source address into an IPv6-encoded IPv4 address. The IPv4
     destination address will be the address with which we have
     previously been configured, through the ip64_set_ipv4_address()
     function. We use the mapping table to look up the new IPv6
     destination address. As we assume that the IPv4 packet is a
     response to a previously sent IPv6 packet, we should have a
     mapping between the (protocol, destport, srcport, srcaddress)
     tuple. If not, we'll return 0 to indicate that we failed to
     translate the packet. */
  if(ip64_addr_4to6(&IP64_IP_BUF->srcipaddr, &UIP_IP_BUF->srcipaddr) == 0) {
    return 0;
  }

    /* For the next header field, we simply use the IPv4 protocol
     field. We only support UDP and TCP packets. */
  switch(IP64_IP_BUF->proto) {
  case IP_PROTO_UDP:
    UIP_IP_BUF->nxthdr = IP_PROTO_UDP;
    break;

  case IP_PROTO_TCP:
    UIP_IP_BUF->nxthdr = IP_PROTO_TCP;
    break;

  case IP_PROTO_ICMPV4:
    /* Allow only ICMPv4 ECHO_REQUESTS (ping packets) through to the
       local IPv6 host. */
    if(IP64_ICMP_BUF->type == ICMP_ECHO) {
      UIP_IP_BUF->nxthdr = IP_PROTO_ICMPV6;
      UIP_ICMP_BUF->type = ICMP6_ECHO;
    } else {
      return 0;
    }
    break;

  default:
    /* For protocol types that we do not support, we return 0 to
       indicate that we failed to translate the packet to an IPv6
       packet. */
    return 0;
  }

  /* Translate IPv4 broadcasts to IPv6 all-nodes multicasts. */
  /* @mcroal:Don't use broadcasts conmunication */
  if((uip_ip4addr_cmp(&IP64_IP_BUF->destipaddr, &ip64_hostaddr))) {
    ip64_addr_copy6(&UIP_IP_BUF->destipaddr, &ipv6_local_address);
  } else {
    /* @mcroal:Transform this destination address to itself IPv6 
     address. */
    m = ip64_addrmap_lookup(NULL, &IP64_IP_BUF->destipaddr);
    if(m == NULL) {
      return 0;
    }
    ip64_addr_copy6(&UIP_IP_BUF->destipaddr, &m->ip6addr);
  }
  
  /* @mcroal:We direct the completin of the conversion for port */  
  
  /* The checksum is in different places in the different protocol
   headers, so we need to be sure that we update the correct
   field. */
  switch(UIP_IP_BUF->nxthdr) {
  case IP_PROTO_TCP:
    UIP_TCP_BUF->tcpchksum = 0;
    UIP_TCP_BUF->tcpchksum = ~(ipv6_transport_checksum(uip_buf,
						  ipv6len,
						  IP_PROTO_TCP));
    break;
  case IP_PROTO_UDP:
    UIP_UDP_BUF->udpchksum = 0;
    UIP_UDP_BUF->udpchksum = ~(ipv6_transport_checksum(uip_buf,
						  ipv6len,
						  IP_PROTO_UDP));
    if(UIP_UDP_BUF->udpchksum == 0) {
      UIP_UDP_BUF->udpchksum = 0xffff;
    }
    break;

  case IP_PROTO_ICMPV6:
    UIP_ICMP_BUF->icmpchksum = 0;
    UIP_ICMP_BUF->icmpchksum = ~(ipv6_transport_checksum(uip_buf,
                                                ipv6len,
                                                IP_PROTO_ICMPV6));
    break;
  default:
    return 0;
  }

  /* Finally, we return the length of the resulting IPv6 packet. */
  return ipv6len;
}
/*---------------------------------------------------------------------------*/

