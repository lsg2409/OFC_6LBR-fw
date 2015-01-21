/*
 * Copyright (c) 2001-2003, Adam Dunkels.
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
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the uIP TCP/IP stack.
 *
 * $Id: uip_arp.c,v 1.8 2010/12/14 22:45:22 dak664 Exp $
 *
 */
#include "contiki-net.h"
#include "cetic-6lbr.h"
#include "eth-drv.h"
#include "ip64.h"
#include "ip64-arp.h"
#include "ip64-addrmap.h"

#include <string.h>
#include <stdio.h>
/*---------------------------------------------------------------------------*/
struct arp_entry {
  uip_ip4addr_t ipaddr;
  struct uip_eth_addr ethaddr;
  uint8_t time;
};
struct arp_hdr {
  uint16_t hwtype;
  uint16_t protocol;
  uint8_t hwlen;
  uint8_t protolen;
  uint16_t opcode;
  struct uip_eth_addr shwaddr;
  uip_ip4addr_t sipaddr;
  struct uip_eth_addr dhwaddr;
  uip_ip4addr_t dipaddr;
};
/*---------------------------------------------------------------------------*/
#define ARP_REQUEST 1
#define ARP_REPLY   2
#define ARP_HWTYPE_ETH 1
#define EVENT_INTERVAL          10 * CLOCK_SECOND

#define BUF                       ((struct uip_eth_hdr *)&ll_header[0])
#define UIP_ARP_BUF               ((struct arp_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_IPV4_BUF              ((struct ipv4_hdr *)&uip_buf[UIP_LLH_LEN])
#define printf(...)
/*---------------------------------------------------------------------------*/
static const struct uip_eth_addr broadcast_ethaddr =
                                            {{0xff,0xff,0xff,0xff,0xff,0xff}};
//static const uint16_t broadcast_ipaddr[2] = {0xffff,0xffff};
static struct arp_entry arp_table[UIP_ARPTAB_SIZE];
static uint8_t arptime;
static uint8_t tmpage;
const uip_ipaddr_t uip_all_zeroes_addr = {{ 0x0,/* rest is 0 */ }};
/*---------------------------------------------------------------------------*/
PROCESS(router_arp_process, "6lbr arp request");
/*---------------------------------------------------------------------------*/
/**
 * Initialize the ARP module.
 *
 */
/*---------------------------------------------------------------------------*/
void
ip64_arp_init(void)
{
  int i;
  for(i = 0; i < UIP_ARPTAB_SIZE; ++i) {
    memset(&arp_table[i].ipaddr, 0, 4);
  }
}
/*---------------------------------------------------------------------------*/
/**
 * Periodic ARP processing function.
 *
 * This function performs periodic timer processing in the ARP module
 * and should be called at regular intervals. The recommended interval
 * is 10 seconds between the calls.
 *
 */
/*---------------------------------------------------------------------------*/
void
ip64_arp_timer(void)
{
  struct arp_entry *tabptr;
  int i;
  
  ++arptime;
  for(i = 0; i < UIP_ARPTAB_SIZE; ++i) {
    tabptr = &arp_table[i];
    if(uip_ip4addr_cmp(&tabptr->ipaddr, &uip_all_zeroes_addr) &&
       arptime - tabptr->time >= UIP_ARP_MAXAGE) {
      memset(&tabptr->ipaddr, 0, 4);
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
arp_update(uip_ip4addr_t *ipaddr, struct uip_eth_addr *ethaddr)
{
  struct arp_entry *tabptr = arp_table;  // &mcroal:Del register
  int i, c;
  
  /* Walk through the ARP mapping table and try to find an entry to
     update. If none is found, the IP -> MAC address mapping is
     inserted in the ARP table. */
  for(i = 0; i < UIP_ARPTAB_SIZE; ++i) {
    tabptr = &arp_table[i];

    /* Only check those entries that are actually in use. */
    if(!uip_ip4addr_cmp(&tabptr->ipaddr, &uip_all_zeroes_addr)) {

      /* Check if the source IP address of the incoming packet matches
         the IP address in this ARP table entry. */
      if(uip_ip4addr_cmp(ipaddr, &tabptr->ipaddr)) {
	 
	/* An old entry found, update this and return. */
	memcpy(tabptr->ethaddr.addr, ethaddr->addr, 6);
	tabptr->time = arptime;

	return;
      }
    }
      tabptr++;
  }

  /* If we get here, no existing ARP table entry was found, so we
     create one. */

  /* First, we try to find an unused entry in the ARP table. */
  for(i = 0; i < UIP_ARPTAB_SIZE; ++i) {
    tabptr = &arp_table[i];
    if(uip_ip4addr_cmp(&tabptr->ipaddr, &uip_all_zeroes_addr)) {
      break;
    }
  }

  /* If no unused entry is found, we try to find the oldest entry and
     throw it away. */
  if(i == UIP_ARPTAB_SIZE) {
    tmpage = 0;
    c = 0;
    for(i = 0; i < UIP_ARPTAB_SIZE; ++i) {
      tabptr = &arp_table[i];
      if(arptime - tabptr->time > tmpage) {
	tmpage = arptime - tabptr->time;
	c = i;
      }
    }
    i = c;
    tabptr = &arp_table[i];
  }

  /* Now, i is the ARP table entry which we will fill with the new
     information. */
  uip_ip4addr_copy(&tabptr->ipaddr, ipaddr);
  memcpy(tabptr->ethaddr.addr, ethaddr->addr, 6);
  tabptr->time = arptime;
}
/*---------------------------------------------------------------------------*/
uint16_t
ip64_arp_arp_input()
{
  struct ip64_addrmap_entry *m;
  
  if(uip_len < sizeof(struct arp_hdr)) {
    /* ip64_arp_arp_input: len too small */
    return 0;
  }

  switch(UIP_ARP_BUF->opcode) {
  case UIP_HTONS(ARP_REQUEST):
    /* ARP request. If it asked for our address, we send out a
       reply. */    
    m = ip64_addrmap_lookup(NULL, &UIP_ARP_BUF->dipaddr);
    if(m != NULL) {
      arp_update(&UIP_ARP_BUF->sipaddr, &UIP_ARP_BUF->shwaddr);
      
      UIP_ARP_BUF->opcode = UIP_HTONS(ARP_REPLY);

      memcpy(UIP_ARP_BUF->dhwaddr.addr, UIP_ARP_BUF->shwaddr.addr, 6);
      memcpy(UIP_ARP_BUF->shwaddr.addr, &eth_mac_addr, 6);
      memcpy(BUF->src.addr, &eth_mac_addr, 6);
      memcpy(BUF->dest.addr, UIP_ARP_BUF->dhwaddr.addr, 6);

      uip_ip4addr_copy(&UIP_ARP_BUF->dipaddr, &UIP_ARP_BUF->sipaddr);
      uip_ip4addr_copy(&UIP_ARP_BUF->sipaddr, &m->ip4addr);

      BUF->type = UIP_HTONS(UIP_ETHTYPE_ARP);
      return sizeof(struct arp_hdr);
    } else if (uip_ip4addr_cmp(&UIP_ARP_BUF->dipaddr, ip64_get_hostaddr())) {
      /* First, we register the one who made the request in our ARP
	 table, since it is likely that we will do more communication
	 with this host in the future. */
      arp_update(&UIP_ARP_BUF->sipaddr, &UIP_ARP_BUF->shwaddr);
      
      UIP_ARP_BUF->opcode = UIP_HTONS(ARP_REPLY);

      memcpy(UIP_ARP_BUF->dhwaddr.addr, UIP_ARP_BUF->shwaddr.addr, 6);
      memcpy(UIP_ARP_BUF->shwaddr.addr, &eth_mac_addr, 6);
      memcpy(BUF->src.addr, &eth_mac_addr, 6);
      memcpy(BUF->dest.addr, UIP_ARP_BUF->dhwaddr.addr, 6);

      uip_ip4addr_copy(&UIP_ARP_BUF->dipaddr, &UIP_ARP_BUF->sipaddr);
      uip_ip4addr_copy(&UIP_ARP_BUF->sipaddr, ip64_get_hostaddr());

      BUF->type = UIP_HTONS(UIP_ETHTYPE_ARP);
      return sizeof(struct arp_hdr);
    }
    break;
  case UIP_HTONS(ARP_REPLY):
    /* ARP reply. We insert or update the ARP table if it was meant
       for us. */
    if(uip_ip4addr_cmp(&UIP_ARP_BUF->dipaddr, ip64_get_hostaddr())) {
      arp_update(&UIP_ARP_BUF->sipaddr, &UIP_ARP_BUF->shwaddr);
    }
    break;
  default:break;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
uint16_t
ip64_arp_check_cache()
{
  uip_ip4addr_t broadcast_addr;
  struct arp_entry *tabptr = arp_table;
  
  /* First check if destination is a local broadcast. */
  uip_ipaddr(&broadcast_addr, 255,255,255,255);
  if(uip_ip4addr_cmp(&UIP_IPV4_BUF->destipaddr, &broadcast_addr)) {
    return 1;
  } else if(UIP_IPV4_BUF->destipaddr.u8[0] == 224) {
    /* Multicast. */
    return 1;
  } else {
    uip_ip4addr_t ipaddr;
    int i;
    /* Check if the destination address is on the local network. */
    if(!uip_ipaddr_maskcmp(&UIP_IPV4_BUF->destipaddr,
			   ip64_get_hostaddr(),
			   ip64_get_netmask())) {
      /* Destination address was not on the local network, so we need to
	 use the default router's IP address instead of the destination
	 address when determining the MAC address. */
      uip_ip4addr_copy(&ipaddr, ip64_get_draddr());
    } else {
      /* Else, we use the destination IP address. */
      uip_ip4addr_copy(&ipaddr, &UIP_IPV4_BUF->destipaddr);
    }
    for(i = 0; i < UIP_ARPTAB_SIZE; ++i) {
      if(uip_ip4addr_cmp(&ipaddr, &tabptr->ipaddr)) {
	break;
      }
      tabptr++;
    }
    if(i == UIP_ARPTAB_SIZE) {
      return 0;
    }
    return 1;
  }
}
/*---------------------------------------------------------------------------*/
uint16_t
ip64_arp_create_ethhdr()
{
  struct arp_entry *tabptr = arp_table;
  uip_ip4addr_t broadcast_addr;
  
  /* Find the destination IP address in the ARP table and construct
     the Ethernet header. If the destination IP addres isn't on the
     local network, we use the default router's IP address instead.

     If not ARP table entry is found, we overwrite the original IP
     packet with an ARP request for the IP address. */

  /* First check if destination is a local broadcast. */
  uip_ipaddr(&broadcast_addr, 255,255,255,255);
  if(uip_ip4addr_cmp(&UIP_IPV4_BUF->destipaddr, &broadcast_addr)) {
    memcpy(&BUF->dest.addr, &broadcast_ethaddr.addr, 6);
  } else if(UIP_IPV4_BUF->destipaddr.u8[0] == 224) {
    /* Multicast. */
    BUF->dest.addr[0] = 0x01;
    BUF->dest.addr[1] = 0x00;
    BUF->dest.addr[2] = 0x5e;
    BUF->dest.addr[3] = UIP_IPV4_BUF->destipaddr.u8[1];
    BUF->dest.addr[4] = UIP_IPV4_BUF->destipaddr.u8[2];
    BUF->dest.addr[5] = UIP_IPV4_BUF->destipaddr.u8[3];
  } else {
    uip_ip4addr_t ipaddr;
    int i;
    /* Check if the destination address is on the local network. */
    if(!uip_ipaddr_maskcmp(&UIP_IPV4_BUF->destipaddr,
			   ip64_get_hostaddr(),
			   ip64_get_netmask())) {
      /* Destination address was not on the local network, so we need to
	 use the default router's IP address instead of the destination
	 address when determining the MAC address. */
      uip_ip4addr_copy(&ipaddr, ip64_get_draddr());          
    } else {
      /* Else, we use the destination IP address. */
      uip_ip4addr_copy(&ipaddr, &UIP_IPV4_BUF->destipaddr);
    }
    for(i = 0; i < UIP_ARPTAB_SIZE; ++i) {
      if(uip_ip4addr_cmp(&ipaddr, &tabptr->ipaddr)) {
	break;
      }
      tabptr++;
    }

    if(i == UIP_ARPTAB_SIZE) {
      return 0;
    }
    memcpy(BUF->dest.addr, tabptr->ethaddr.addr, 6);
  }
  memcpy(BUF->src.addr, &eth_mac_addr, 6);
  
  BUF->type = UIP_HTONS(UIP_ETHTYPE_IP);
  return sizeof(struct uip_eth_hdr);
}
/*---------------------------------------------------------------------------*/
uint16_t
ip64_arp_create_arp_request()
{
  uip_ip4addr_t ipaddr;
  
  if(!uip_ipaddr_maskcmp(&UIP_IPV4_BUF->destipaddr,
			 ip64_get_hostaddr(),
			 ip64_get_netmask())) {
    /* Destination address was not on the local network, so we need to
       use the default router's IP address instead of the destination
       address when determining the MAC address. */
    uip_ip4addr_copy(&ipaddr, ip64_get_draddr());
  } else {
    /* Else, we use the destination IP address. */
    uip_ip4addr_copy(&ipaddr, &UIP_IPV4_BUF->destipaddr);
  }
  
  memset(BUF->dest.addr, 0xff, 6);         
  memset(UIP_ARP_BUF->dhwaddr.addr, 0x00, 6);
  memcpy(BUF->src.addr, &eth_mac_addr, 6);
  memcpy(UIP_ARP_BUF->shwaddr.addr, &eth_mac_addr, 6);

  uip_ip4addr_copy(&UIP_ARP_BUF->dipaddr, &ipaddr);
  uip_ip4addr_copy(&UIP_ARP_BUF->sipaddr, ip64_get_hostaddr());
  UIP_ARP_BUF->opcode = UIP_HTONS(ARP_REQUEST);
  UIP_ARP_BUF->hwtype = UIP_HTONS(ARP_HWTYPE_ETH);
  UIP_ARP_BUF->protocol = UIP_HTONS(UIP_ETHTYPE_IP);
  UIP_ARP_BUF->hwlen = 6;
  UIP_ARP_BUF->protolen = 4;
  BUF->type = UIP_HTONS(UIP_ETHTYPE_ARP);
  
  uip_appdata = &uip_buf[UIP_TCPIP_HLEN + UIP_LLH_LEN];

  return sizeof(struct arp_hdr);
}
/*---------------------------------------------------------------------------*/
uint16_t
ip64_arp_periodic_arp_request()
{   
  memset(BUF->dest.addr, 0xff, 6);         
  memset(UIP_ARP_BUF->dhwaddr.addr, 0x00, 6);
  memcpy(BUF->src.addr, &eth_mac_addr, 6);
  memcpy(UIP_ARP_BUF->shwaddr.addr, &eth_mac_addr, 6);

  uip_ip4addr_copy(&UIP_ARP_BUF->dipaddr, ip64_get_draddr());
  uip_ip4addr_copy(&UIP_ARP_BUF->sipaddr, ip64_get_hostaddr());
  UIP_ARP_BUF->opcode = UIP_HTONS(ARP_REQUEST);
  UIP_ARP_BUF->hwtype = UIP_HTONS(ARP_HWTYPE_ETH);
  UIP_ARP_BUF->protocol = UIP_HTONS(UIP_ETHTYPE_IP);
  UIP_ARP_BUF->hwlen = 6;
  UIP_ARP_BUF->protolen = 4;
  BUF->type = UIP_HTONS(UIP_ETHTYPE_ARP);
  
  uip_appdata = &uip_buf[UIP_TCPIP_HLEN + UIP_LLH_LEN];

  return sizeof(struct arp_hdr);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(router_arp_process, ev, data)
{
  static int counter;
  static struct etimer periodic_timer;
  PROCESS_BEGIN();
  
  etimer_set(&periodic_timer, EVENT_INTERVAL);
  while(1) {
    PROCESS_WAIT_EVENT();
    if(etimer_expired(&periodic_timer)) {
      ip64_arp_timer();
      counter++;
      if(counter == 3)
      {
        counter = 0;
        uip_len = ip64_arp_periodic_arp_request();
        eth_drv_send();
      }
      etimer_restart(&periodic_timer);
    }
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
