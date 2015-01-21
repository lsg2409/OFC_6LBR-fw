/*
 * Copyright (c) 2012, Thingsquare, http://www.thingsquare.com/.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#ifndef IP64_H
#define IP64_H

#include "uip.h"
/*---------------------------------------------------------------------------*/
struct ipv6_hdr {
  uint8_t vtc;
  uint8_t tcflow;
  uint16_t flow;
  uint8_t len[2];
  uint8_t nxthdr, hoplim;
  uip_ip6addr_t srcipaddr, destipaddr;
};

struct ipv4_hdr {
  uint8_t vhl,
    tos,
    len[2],
    ipid[2],
    ipoffset[2],
    ttl,
    proto;
  uint16_t ipchksum;
  uip_ip4addr_t srcipaddr, destipaddr;
};

struct tcp_hdr {
  uint16_t srcport;
  uint16_t destport;
  uint8_t seqno[4];
  uint8_t ackno[4];
  uint8_t tcpoffset;
  uint8_t flags;
  uint8_t  wnd[2];
  uint16_t tcpchksum;
  uint8_t urgp[2];
  uint8_t optdata[4];
};

struct udp_hdr {
  uint16_t srcport;
  uint16_t destport;
  uint16_t udplen;
  uint16_t udpchksum;
};

struct icmpv4_hdr {
  uint8_t type, icode;
  uint16_t icmpchksum;
};

struct icmpv6_hdr {
  uint8_t type, icode;
  uint16_t icmpchksum;
  uint16_t id, seqno;
};

/*---------------------------------------------------------------------------*/
void ip64_init(void);
uint16_t ip64_6to4(void);
uint16_t ip64_4to6(void);
void ip64_set_ipv4_address(const uip_ip4addr_t *ipv4addr,
			   const uip_ip4addr_t *netmask);
void ip64_set_ipv6_address(const uip_ip6addr_t *ipv6addr);

const uip_ip4addr_t *ip64_get_hostaddr(void);
const uip_ip4addr_t *ip64_get_netmask(void);
const uip_ip4addr_t *ip64_get_draddr(void);

void ip64_set_hostaddr(const uip_ip4addr_t *hostaddr);
void ip64_set_netmask(const uip_ip4addr_t *netmask);
void ip64_set_draddr(const uip_ip4addr_t *draddr);

extern uip_buf_t ip64_packet_buffer_aligned;

#endif /* IP64_H */

