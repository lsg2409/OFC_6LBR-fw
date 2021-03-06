/*
 * Copyright (c) 2013, CETIC.
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * \file
 *         6LBR Web Server
 * \author
 *         6LBR Team <6lbr@cetic.be>
 */

#define LOG6LBR_MODULE "WEB"

#include "net/ipv6/uip-nd6.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-ds6-nbr.h"
#include "net/ipv6/uip-ds6-route.h"
#include "net/mac/csma.h"
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ip/uip.h"
#include "net/netstack.h"
#include "net/rpl/rpl.h"
#include "net/rpl/rpl-private.h"

#include "sicslow-ethernet.h"
#include "cetic-6lbr.h"
#include "nvm-config.h"
#include "rio.h"
#include "node-info.h"
#include "bsp.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>              /* For printf() */
#define DEBUG DEBUG_NONE
#include "net/ip/uip-debug.h"

extern uip_ds6_nbr_t uip_ds6_nbr_cache[];
extern uip_ds6_prefix_t uip_ds6_prefix_list[];

extern rpl_instance_t instance_table[RPL_MAX_INSTANCES];

extern uint32_t slip_sent;
extern uint32_t slip_received;
extern uint32_t slip_message_sent;
extern uint32_t slip_message_received;

static int redirect;

/*---------------------------------------------------------------------------*/
/* Use simple webserver with only one page for minimum footprint.
 * Multiple connections can result in interleaved tcp segments since
 * a single static buffer is used for all segments.
 */
#include "httpd-simple.h"
/* The internal webserver can provide additional information if
 * enough program flash is available.
 */
#define WEBSERVER_CONF_LOADTIME 1
#define WEBSERVER_CONF_FILESTATS 1

#define BUF_USES_STACK 0
/*---------------------------------------------------------------------------*/
PROCESS(webserver_nogui_process, "Web server");
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(webserver_nogui_process, ev, data)
{
  PROCESS_BEGIN();

  httpd_init();

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(ev == tcpip_event);
    httpd_appcall(data);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
#define BUF_SIZE (10*256)
static const char *TOP =
  "<html><body><style>body{color:#373737;background:#212121;font-family:Calibri;padding:0}"
  ".outer{width:100%;}"
  ".inner{position:relative;max-width:640px;margin: 0 auto;}"
  "#header_wrap{margin:0 auto;background:#212121;}"
  "#header_wrap .inner{padding:50px 90px 30px 10px;}"
  "#forkme_banner{position:absolute;top:0;right:10px;padding:10px 50px 10px 10px;color:#fff;background:#0090ff;font-size: 18px;font-weight: 700;box-shadow: 0 0 10px rgba(0,204,153,.9);}"
  "#project_title{margin:0;color:#fff;font-size:42px;font-weight:700;font-family:Calibri;text-shadow:#8E8E8E 0px 0px 10px;}"
  ".menu-general a {padding:3px 25px 4px;height:23px;line-height: 39px;font-family:Arial;font-size: 17px;font-weight: 700;margin-right: 0px;}"
  ".menu-general a:link, .menu-general a:visited {color: #0090ff;text-decoration:none;}"
  ".menu-general a:hover {color: #FFFFFF;background-color:#333333;text-decoration:none;}"
  "#main_wrap{background:#f2f2f2; margin:0 auto}"
  "#intro_home {background: #f2f2f2;font-size: 26px;font-weight: bold; text-align:center}"
  "#left_home {background: #f2f2f2;}"
  "#left_home table,#left_home tr,#left_home td{border-collapse:collapse;border: 1px solid #333;}"
  "tr.row_first{background:#FFC;font-weight:bold;}"
  "#left_home td{padding:5px;}"
  "h1{font-size: 18px; font-weight: bold; color: #333333; line-height: 18px;}"
  "#footer{color: #0090ff;font-family:Arial;font-size:14px;line-height: 18px;}	";
static const char *BODY =
  "</style><div id=\"header_wrap\" class=\"outer\"><header class=\"inner\">"
  "<a id=\"forkme_banner\">ofc-6lbr</a>"
  "<h1 id=\"project_title\">6LoWPAN Border Router</h1></header>"
  "<section class=\"menu-general\" align=\"center\">"
  "<a href=\"/\">Info</a>"
  "<a href=\"/sensors.html\">Sensors</a>"
  "<a href=\"/rpl.html\">RPL</a>"
  "<a href=\"/network.html\">Network</a>"
  "<a href=\"/config.html\">Config</a>"
  "<a href=\"/statistics.html\">Statistics</a>"
  "<a href=\"/admin.html\">Administration</a>"
  "</section></div>\n"
  "<div id=\"main_wrap\" class=\"outer\">";
static const char *BOTTOM = "</body></html>";

#if BUF_USES_STACK
static char *bufptr, *bufend;
#else
static char buf[BUF_SIZE];
static int blen;
#endif
/*---------------------------------------------------------------------------*/
/*OPTIMIZATIONS to gain space : prototypes*/
static void add(char *str, ...);
static void add_div_home(char const *title);
static void add_div_footer();
static void add_network_cases(const uint8_t state);
static void reset_buf();
/*End optimizations*/
/*---------------------------------------------------------------------------*/
static void
ipaddr_add(const uip_ipaddr_t * addr)
{
  uint16_t a;
  int i, f;

  for(i = 0, f = 0; i < sizeof(uip_ipaddr_t); i += 2) {
    a = (addr->u8[i] << 8) + addr->u8[i + 1];
    if(a == 0 && f >= 0) {
      if(f++ == 0)
        add("::");
    } else {
      if(f > 0) {
        f = -1;
      } else if(i > 0) {
        add(":");
      }
      add("%x", a);
    }
  }
}
static void
ipaddr_add_u8(const uint8_t * addr)
{
  uint16_t a;
  int i, f;

  for(i = 0, f = 0; i < 16; i += 2) {
    a = (addr[i] << 8) + addr[i + 1];
    if(a == 0 && f >= 0) {
      if(f++ == 0)
        add("::");
    } else {
      if(f > 0) {
        f = -1;
      } else if(i > 0) {
        add(":");
      }
      add("%x", a);
    }
  }
}
static void
lladdr_add(const uip_lladdr_t * addr)
{
  int i;

  for(i = 0; i < sizeof(uip_lladdr_t); i++) {
    if(i > 0) {
      add(":");
    }
    add("%x", addr->addr[i]);
  }
}
static void
ethaddr_add(ethaddr_t * addr)
{
  int i;

  for(i = 0; i < 6; i++) {
    if(i > 0) {
      add(":");
    }

    add("%x", (*addr)[i]);
  }
}
/*---------------------------------------------------------------------------*/
#if CONTIKI_TARGET_ECONOTAG
extern void _start;

//Code
extern void _etext;

//RO data
extern void __data_start;

//Initialised data
extern void _edata;

//Stack
extern void __bss_start;

//Zero initialised data
extern void _bss_end__;

//Heap
extern void _end;
#endif
/*---------------------------------------------------------------------------*/
static
PT_THREAD(generate_index(struct httpd_state *s))
{
  static int i;

#if BUF_USES_STACK
  char buf[BUF_SIZE];
#endif
#if WEBSERVER_CONF_LOADTIME
  static clock_time_t numticks;

  numticks = clock_time();
#endif

  PSOCK_BEGIN(&s->sout);

  SEND_STRING(&s->sout, TOP);
  SEND_STRING(&s->sout, BODY);
  reset_buf();
  add_div_home("Info");
  add("<div id=\"left_home\"class=\"inner\">");
  add("<h2>Info</h2>");
  add("Version : " CETIC_6LBR_VERSION " (" CONTIKI_VERSION_STRING ")<br />");
  add("Mode : ");
#if CETIC_6LBR_SMARTBRIDGE
  add("SMART BRIGDE");
#endif
#if CETIC_6LBR_TRANSPARENTBRIDGE
#if CETIC_6LBR_LEARN_RPL_MAC
  add("RPL Relay");
#else
  add("FULL TRANSPARENT BRIGDE");
#endif
#endif
#if CETIC_6LBR_ROUTER
#if UIP_CONF_IPV6_RPL
  add("RPL ROUTER");
#else
  add("NDP ROUTER");
#endif
#endif
#if CETIC_6LBR_6LR
  add("6LR");
#endif
  add("<br />\n");
  i = clock_seconds() - cetic_6lbr_startup;
  add("Uptime : %dh %dm %ds<br />", i / 3600, (i / 60) % 60, i % 60);
  SEND_STRING(&s->sout, buf);
  reset_buf();

  add("<br /><h2>WSN</h2>");
  add("MAC: %s<br />RDC: %s (channel check interval-%d Hz)<br />",
      NETSTACK_MAC.name,
      NETSTACK_RDC.name,
      (NETSTACK_RDC.channel_check_interval() ==
       0) ? 0 : CLOCK_SECOND / NETSTACK_RDC.channel_check_interval());
#if UIP_CONF_IPV6_RPL
  add("Prefix : ");
  ipaddr_add(&cetic_dag->prefix_info.prefix);
  add("/%d", cetic_dag->prefix_info.length);
  add("<br />");
#endif
  add("HW address : ");
  lladdr_add(&uip_lladdr);
  add("<br />");
  SEND_STRING(&s->sout, buf);
  reset_buf();

  add("<br /><h2>Ethernet</h2>");
#if CETIC_6LBR_ROUTER
  add("Address : ");
  ipaddr_add(&eth_ip_addr);
  add("<br />");
  add("Local address : ");
  ipaddr_add(&eth_ip_local_addr);
  add("<br />");
#endif
  add("HW address : ");
  ethaddr_add(&eth_mac_addr);
  add("<br />");
  SEND_STRING(&s->sout, buf);
  reset_buf();

  
#if WEBSERVER_CONF_FILESTATS
  static uint16_t numtimes;

  add("<br><i>This page sent %u times</i>", ++numtimes);
#endif

#if WEBSERVER_CONF_LOADTIME
  numticks = clock_time() - numticks + 1;
  add(" <i>(%u.%02u sec)</i>", numticks / CLOCK_SECOND,
      (100 * (numticks % CLOCK_SECOND) / CLOCK_SECOND));
#endif
  add("</div>");
  
  add_div_footer();
  SEND_STRING(&s->sout, buf);
  SEND_STRING(&s->sout, BOTTOM);

  PSOCK_END(&s->sout);
}
/*---------------------------------------------------------------------------*/
static
PT_THREAD(generate_sensors(struct httpd_state *s))
{
  static int i;

#if BUF_USES_STACK
  char buf[BUF_SIZE];
#endif
#if WEBSERVER_CONF_LOADTIME
  static clock_time_t numticks;

  numticks = clock_time();
#endif

  PSOCK_BEGIN(&s->sout);

  SEND_STRING(&s->sout, TOP);
  SEND_STRING(&s->sout, BODY);
  reset_buf();
  add_div_home("Sensors");
  add("<div id=\"left_home\"class=\"inner\">");
  add("<table align=\"center\">"
     "<tbody><tr class=\"row_first\"><td>Node</td><td>Type</td><td>Web</td><td>Coap</td><td>Sequence</td><td>Parent</td><td>Last seen</td></tr>"
     "</tbody>");
  SEND_STRING(&s->sout, buf);
  reset_buf();

  for(i = 0; i < UIP_DS6_ROUTE_NB; i++) {
    if(node_info_table[i].isused) {
      add("<tr><td>");     
      ipaddr_add(&node_info_table[i].ipaddr);
      add("</a></td>");      
      add("<td>CC2530DK</td>");      
      SEND_STRING(&s->sout, buf);
      reset_buf();
      add("<td><a href=http://[");
      ipaddr_add(&node_info_table[i].ipaddr);
      add("]/>web</a></td>");
      add("<td><a href=coap://[");
      ipaddr_add(&node_info_table[i].ipaddr);
      add("]:5683/>coap</a></td>");
      if(node_info_table[i].messages_count > 0) {
        add("<td>%d</td><td>", node_info_table[i].sequence);
        ipaddr_add(&node_info_table[i].ip_parent);
        add("</td>");
      } else {
        add("<td></td><td></td>");
      }
      add("<td>%d</td>",
          (clock_time() - node_info_table[i].last_seen) / CLOCK_SECOND);
      add("</tr>");
      SEND_STRING(&s->sout, buf);
      reset_buf();
    }
  }
  add("</tbody></table><br />");
  SEND_STRING(&s->sout, buf);
  reset_buf();

  add("<center>"
     "<img src=\"http://chart.googleapis.com/chart?cht=gv&chls=1&chl=digraph{");
  add("_%04x;",(uip_lladdr.addr[6] << 8) + uip_lladdr.addr[7]);

  for(i = 0; i < UIP_DS6_ROUTE_NB; i++) {
    if(node_info_table[i].isused) {
      if(! uip_is_addr_unspecified(&node_info_table[i].ip_parent)) {
        add("_%04hx->_%04hx;",
            (node_info_table[i].ipaddr.u8[14] << 8) +
            node_info_table[i].ipaddr.u8[15],
            (node_info_table[i].ip_parent.u8[14] << 8) +
            node_info_table[i].ip_parent.u8[15]);         
      }
    }
  }
  add("}\"alt=\"\" /></center>");
  SEND_STRING(&s->sout, buf);
  reset_buf();

#if WEBSERVER_CONF_FILESTATS
  static uint16_t numtimes;

  add("<br><i>This page sent %u times</i>", ++numtimes);
#endif

#if WEBSERVER_CONF_LOADTIME
  numticks = clock_time() - numticks + 1;
  add(" <i>(%u.%02u sec)</i>", numticks / CLOCK_SECOND,
      (100 * (numticks % CLOCK_SECOND) / CLOCK_SECOND));
#endif
  add("</div>");
  
  add_div_footer();
  SEND_STRING(&s->sout, buf);
  SEND_STRING(&s->sout, BOTTOM);

  PSOCK_END(&s->sout);
}
/*---------------------------------------------------------------------------*/

static
PT_THREAD(generate_rpl(struct httpd_state *s))
{
#if UIP_CONF_IPV6_RPL
  static int i;
  static int j;
#endif

#if BUF_USES_STACK
  char buf[BUF_SIZE];
#endif
#if WEBSERVER_CONF_LOADTIME
  static clock_time_t numticks;

  numticks = clock_time();
#endif

  PSOCK_BEGIN(&s->sout);

  SEND_STRING(&s->sout, TOP);
  SEND_STRING(&s->sout, BODY);
  reset_buf();

  add_div_home("RPL");
  add("<div id=\"left_home\"class=\"inner\">");
  SEND_STRING(&s->sout, buf);
  reset_buf();
#if UIP_CONF_IPV6_RPL
  add("<h2>Configuration</h2>");
  add("Lifetime : %d (%d x %d s)<br />",
      RPL_CONF_DEFAULT_LIFETIME * RPL_CONF_DEFAULT_LIFETIME_UNIT,
      RPL_CONF_DEFAULT_LIFETIME, RPL_CONF_DEFAULT_LIFETIME_UNIT);
  add("<br />");
  SEND_STRING(&s->sout, buf);
  reset_buf();
  for(i = 0; i < RPL_MAX_INSTANCES; ++i) {
    if(instance_table[i].used) {
      add("<h2>Instance %d</h2>", instance_table[i].instance_id);
      for(j = 0; j < RPL_MAX_DAG_PER_INSTANCE; ++j) {
        if(instance_table[i].dag_table[j].used) {
          add("<h3>DODAG %d</h3>", j);
          add("DODAG ID : ");
          ipaddr_add(&instance_table[i].dag_table[j].dag_id);
          SEND_STRING(&s->sout, buf);
          reset_buf();
          add("<br />Version : %d", instance_table[i].dag_table[j].version);
          add("<br />Grounded : %s",
              instance_table[i].dag_table[j].grounded ? "Yes" : "No");
          add("<br />Preference : %d",
              instance_table[i].dag_table[j].preference);
          add("<br />Mode of Operation : %u", instance_table[i].mop);
          add("<br />Current DIO Interval [%u-%u] : %u",
              instance_table[i].dio_intmin,
              instance_table[i].dio_intmin + instance_table[i].dio_intdoubl,
              instance_table[i].dio_intcurrent);
          add("<br />Objective Function Code Point : %u",
              instance_table[i].of->ocp);
          add("<br />Joined : %s",
              instance_table[i].dag_table[j].joined ? "Yes" : "No");
          add("<br />Rank : %d", instance_table[i].dag_table[j].rank);
          add("<br />");
          SEND_STRING(&s->sout, buf);
          reset_buf();
        }
      }
    }
  }
  if ((nvm_data.global_flags & CETIC_GLOBAL_DISABLE_CONFIG) == 0) {
    add("<br /><h3>Actions</h3>");
    add("<form action=\"rpl-gr\" method=\"get\">");
    add("<input type=\"submit\" value=\"Trigger global repair\"/></form><br />");
    add("<form action=\"rpl-reset\" method=\"get\">");
    add("<input type=\"submit\" value=\"Reset DIO timer\"/></form><br />");
    add("<form action=\"rpl-child\" method=\"get\">");
    add("<input type=\"submit\" value=\"Trigger child DIO\"/></form><br />");
  } else {
    add("<br /><h3>Actions</h3>");
    add("Disabled<br />");
  }
  SEND_STRING(&s->sout, buf);
  reset_buf();
#else
  add("<h3>RPL is deactivated</h3>");
#endif
  
#if WEBSERVER_CONF_FILESTATS
  static uint16_t numtimes;

  add("<br><i>This page sent %u times</i>", ++numtimes);
#endif

#if WEBSERVER_CONF_LOADTIME
  numticks = clock_time() - numticks + 1;
  add(" <i>(%u.%02u sec)</i>", numticks / CLOCK_SECOND,
      (100 * (numticks % CLOCK_SECOND) / CLOCK_SECOND));
#endif
  add("</div>");
  
  add_div_footer();
  SEND_STRING(&s->sout, buf);
  SEND_STRING(&s->sout, BOTTOM);

  PSOCK_END(&s->sout);
}

/*---------------------------------------------------------------------------*/

static
PT_THREAD(generate_network(struct httpd_state *s))
{
  static int i;
  static uip_ds6_route_t *r;
//  static uip_ds6_defrt_t *dr;
  static uip_ds6_nbr_t *nbr;

#if BUF_USES_STACK
  char buf[BUF_SIZE];
#endif
#if WEBSERVER_CONF_LOADTIME
  static clock_time_t numticks;

  numticks = clock_time();
#endif

  PSOCK_BEGIN(&s->sout);

  SEND_STRING(&s->sout, TOP);
  if(redirect) {
    //Quick hack to rewrite url after route or neighbour removal
    SEND_STRING(&s->sout,
                "<meta http-equiv=\"refresh\" content=\"0; url=/network.html\" />");
  }
  SEND_STRING(&s->sout, BODY);
  reset_buf();

  add_div_home("Network");
  add("<div id=\"left_home\"class=\"inner\">");
  add("<br /><h2>Addresses</h2><pre>");
  SEND_STRING(&s->sout, buf);
  reset_buf();

  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    if(uip_ds6_if.addr_list[i].isused) {
      ipaddr_add(&uip_ds6_if.addr_list[i].ipaddr);
      char flag;

      if(uip_ds6_if.addr_list[i].state == ADDR_TENTATIVE) {
        flag = 'T';
      } else if(uip_ds6_if.addr_list[i].state == ADDR_PREFERRED) {
        flag = 'P';
      } else {
        flag = '?';
      }
      add(" %c", flag);
      if(uip_ds6_if.addr_list[i].type == ADDR_MANUAL) {
        flag = 'M';
      } else if(uip_ds6_if.addr_list[i].type == ADDR_DHCP) {
        flag = 'D';
      } else if(uip_ds6_if.addr_list[i].type == ADDR_AUTOCONF) {
        flag = 'A';
      } else {
        flag = '?';
      }
      add(" %c", flag);
      if(!uip_ds6_if.addr_list[i].isinfinite) {
        add(" %u s", stimer_remaining(&uip_ds6_if.addr_list[i].vlifetime));
      }
      add("\n");
      SEND_STRING(&s->sout, buf);
      reset_buf();
    }
  }

  add("</pre><h2>Prefixes</h2><pre>");
  for(i = 0; i < UIP_DS6_PREFIX_NB; i++) {
    if(uip_ds6_prefix_list[i].isused) {
      ipaddr_add(&uip_ds6_prefix_list[i].ipaddr);
      add(" ");
#if UIP_CONF_ROUTER
      if(uip_ds6_prefix_list[i].advertise) {
        add("A");
      }
#else
      if(uip_ds6_prefix_list[i].isinfinite) {
        add("I");
      }
#endif
      add("\n");
    }
  }
  SEND_STRING(&s->sout, buf);
  reset_buf();

  add("</pre><h2>Neighbors</h2><pre>");

  for(nbr = nbr_table_head(ds6_neighbors);
      nbr != NULL;
      nbr = nbr_table_next(ds6_neighbors, nbr)) {

    if ((nvm_data.global_flags & CETIC_GLOBAL_DISABLE_CONFIG) == 0) {
      add("[<a href=\"nbr_rm?");
      ipaddr_add(&nbr->ipaddr);
      add("\">del</a>] ");
    }

    ipaddr_add(&nbr->ipaddr);
    add(" ");
    lladdr_add(uip_ds6_nbr_get_ll(nbr));
    add(" ");
    add_network_cases(nbr->state);
    add("\n");
    SEND_STRING(&s->sout, buf);
    reset_buf();
  }

  add("</pre><h2>Routes</h2><pre>");
  SEND_STRING(&s->sout, buf);
  reset_buf();
  for(r = uip_ds6_route_head(), i = 0; r != NULL;r = uip_ds6_route_next(r), ++i) 
  {
    if ((nvm_data.global_flags & CETIC_GLOBAL_DISABLE_CONFIG) == 0) {
      add("[<a href=\"route_rm?");
      ipaddr_add(&r->ipaddr);
      add("\">del</a>] ");
    }

    ipaddr_add(&r->ipaddr);
    add("/%u via ", r->length);
    ipaddr_add(uip_ds6_route_nexthop(r));

    if(1 || (r->state.lifetime < 600)) {
      add(" %lu s\n", r->state.lifetime);
    } else {
      add("\n");
    }
    SEND_STRING(&s->sout, buf);
    reset_buf();
  }

//  add("</pre><h2>Default Routers</h2><pre>");
//
//  for(dr = uip_ds6_defrt_list_head(); dr != NULL; dr = list_item_next(r)) {
//    ipaddr_add(&dr->ipaddr);
//    if(!dr->isinfinite) {
//      add(" %u s", stimer_remaining(&dr->lifetime));
//    }
//    add("\n");
//    SEND_STRING(&s->sout, buf);
//    reset_buf();
//  }

#if UIP_CONF_DS6_ROUTE_INFORMATION
//  add("</pre><h2>Route info</h2><pre>");
//  for(i = 0; i < UIP_DS6_ROUTE_INFO_NB; i++) {
//    if(uip_ds6_route_info_list[i].isused) {
//      ipaddr_add(&uip_ds6_route_info_list[i].ipaddr);
//      add("/%u (%x) %us\n", uip_ds6_route_info_list[i].length,
//          uip_ds6_route_info_list[i].flags,
//          uip_ds6_route_info_list[i].lifetime);
//    }
//  }
//  SEND_STRING(&s->sout, buf);
//  reset_buf();
#endif

#if CETIC_6LBR_TRANSPARENTBRIDGE
  add("</pre><h2>HW Prefixes cache</h2><pre>");
  for(i = 0; i < prefixCounter; i++) {
    add("%02x:%02x:%02x\n", prefixBuffer[i][0], prefixBuffer[i][1],
        prefixBuffer[i][2]);
  }
  SEND_STRING(&s->sout, buf);
  reset_buf();
  add("</pre><br />");
#endif

  
#if WEBSERVER_CONF_FILESTATS
  static uint16_t numtimes;

  add("<br><i>This page sent %u times</i>", ++numtimes);
#endif

#if WEBSERVER_CONF_LOADTIME
  numticks = clock_time() - numticks + 1;
  add(" <i>(%u.%02u sec)</i>", numticks / CLOCK_SECOND,
      (100 * (numticks % CLOCK_SECOND) / CLOCK_SECOND));
#endif
  add("</div>");
  
  add_div_footer();
  SEND_STRING(&s->sout, buf);
  SEND_STRING(&s->sout, BOTTOM);

  PSOCK_END(&s->sout);
}
/*---------------------------------------------------------------------------*/

#define INPUT_FLAG(name, nvm_name, flag, text, on_text, off_text) \
  if ((nvm_data.global_flags & CETIC_GLOBAL_DISABLE_CONFIG) == 0) { \
    add(text " : <br />" \
	  "<input type=\"radio\" name=\""name"\" value=\"1\" %s> "on_text" <br />", \
	  (nvm_data.nvm_name & (flag)) != 0 ? "checked" : ""); \
	add("<input type=\"radio\" name=\""name"\" value=\"0\" %s> "off_text" <br />", \
      (nvm_data.nvm_name & (flag)) == 0 ? "checked" : ""); \
  } else { \
    add(text " : %s<br />", (nvm_data.nvm_name & (flag)) != 0 ? on_text : off_text ); \
  }

#define INPUT_FLAG_CB(name, nvm_name, flag, text) \
  if ((nvm_data.global_flags & CETIC_GLOBAL_DISABLE_CONFIG) == 0) { \
    add("<input type=\"checkbox\" name=\""name"\" value=\"1\" %s> " text "<br />", \
	  (nvm_data.nvm_name & (flag)) != 0 ? "checked" : ""); \
  } else { \
    add(text " : %s<br />", (nvm_data.nvm_name & (flag)) != 0 ? "on" : "off" ); \
  }

#define INPUT_IPADDR(name, nvm_name, text) \
  if ((nvm_data.global_flags & CETIC_GLOBAL_DISABLE_CONFIG) == 0) { \
    add(text " : <input type=\"text\" name=\""name"\" value=\""); \
      ipaddr_add_u8(nvm_data.nvm_name); \
    add("\" /><br />"); \
  } else { \
    add(text " : "); \
    ipaddr_add_u8(nvm_data.nvm_name); \
    add("<br />"); \
  }

#define INPUT_INT(name, nvm_name, text) \
  if ((nvm_data.global_flags & CETIC_GLOBAL_DISABLE_CONFIG) == 0) { \
    add(text " : <input type=\"text\" name=\""name"\" value=\"%d\" /><br />", nvm_data.nvm_name); \
  } else { \
    add(text " : %d<br />", nvm_data.nvm_name); \
  }

static
PT_THREAD(generate_config(struct httpd_state *s))
{
#if BUF_USES_STACK
  char buf[BUF_SIZE];
#endif
#if WEBSERVER_CONF_LOADTIME
  static clock_time_t numticks;

  numticks = clock_time();
#endif

  PSOCK_BEGIN(&s->sout);

  SEND_STRING(&s->sout, TOP);
  SEND_STRING(&s->sout, BODY);
  reset_buf();
  add_div_home("Configuration");
  add("<div id=\"left_home\"class=\"inner\"><form action=\"config\" method=\"get\">");
  add("<h2>WSN Network</h2>");
  add("<h3>WSN configuration</h3>");
  INPUT_INT("channel", channel, "Channel");
  SEND_STRING(&s->sout, buf);
  reset_buf();

  add("<h3>IP configuration</h3>");
#if CETIC_6LBR_SMARTBRIDGE || CETIC_6LBR_TRANSPARENTBRIDGE
#if CETIC_6LBR_SMARTBRIDGE
  INPUT_FLAG_CB("smart_multi", mode, CETIC_MODE_SMART_MULTI_BR, "Multi-BR support");
#endif
  INPUT_FLAG_CB("wait_ra", mode, CETIC_MODE_WAIT_RA_MASK, "Network autoconfiguration");
  SEND_STRING(&s->sout, buf);
  reset_buf();
  INPUT_IPADDR("wsn_pre", wsn_net_prefix, "Prefix");
  INPUT_INT("wsn_pre_len", wsn_net_prefix_len, "Prefix length");
  SEND_STRING(&s->sout, buf);
  reset_buf();
  INPUT_IPADDR("eth_dft", eth_dft_router, "Default router");
#elif CETIC_6LBR_ROUTER
  INPUT_IPADDR("wsn_pre", wsn_net_prefix, "Prefix");
  INPUT_INT("wsn_pre_len", wsn_net_prefix_len, "Prefix length");
#endif
  SEND_STRING(&s->sout, buf);
  reset_buf();
  INPUT_FLAG_CB("wsn_auto", mode, CETIC_MODE_WSN_AUTOCONF, "Address autoconfiguration");
  INPUT_IPADDR("wsn_addr", wsn_ip_addr, "Manual address");
  SEND_STRING(&s->sout, buf);
  reset_buf();

#if CETIC_6LBR_ROUTER
  add("<br /><h2>Eth Network</h2>");
  add("<h3>IP configuration</h3>");
  INPUT_IPADDR("eth_pre", eth_net_prefix, "Prefix");
  INPUT_INT("eth_pre_len", eth_net_prefix_len, "Prefix length");
  SEND_STRING(&s->sout, buf);
  reset_buf();

  INPUT_FLAG_CB("eth_auto", mode, CETIC_MODE_ETH_AUTOCONF, "Address autoconfiguration" );
  INPUT_IPADDR("eth_addr", eth_ip_addr, "Manual address");
  SEND_STRING(&s->sout, buf);
  reset_buf();
  INPUT_IPADDR("eth_dft", eth_dft_router, "Peer router");
  SEND_STRING(&s->sout, buf);
  reset_buf();
//  add("<br /><h2>RA Daemon</h2>");
//  INPUT_FLAG("ra_daemon", mode, CETIC_MODE_ROUTER_RA_DAEMON, "RA Daemon", "active", "inactive");
//  INPUT_INT("ra_lifetime", ra_router_lifetime, "Router lifetime");
//  SEND_STRING(&s->sout, buf);
//  reset_buf();
  add("<br /><h3>RA</h3>");
  INPUT_INT( "ra_max_interval", ra_max_interval, "Max interval");
  INPUT_INT( "ra_min_interval", ra_min_interval, "Min interval");
  INPUT_INT( "ra_min_delay", ra_min_delay, "Min delay");
  SEND_STRING(&s->sout, buf);
  reset_buf();
  add("<br /><h3>RA Prefix</h3>");
  INPUT_FLAG_CB( "ra_pio", ra_prefix_flags, CETIC_6LBR_MODE_SEND_PIO, "Send Prefix Information");
  INPUT_FLAG_CB( "ra_prefix_o", ra_prefix_flags, UIP_ND6_RA_FLAG_ONLINK, "Prefix on-link");
  INPUT_FLAG_CB( "ra_prefix_a", ra_prefix_flags, UIP_ND6_RA_FLAG_AUTONOMOUS, "Allow autoconfiguration");
  SEND_STRING(&s->sout, buf);
  reset_buf();
  INPUT_INT( "ra_prefix_vtime", ra_prefix_vtime, "Prefix valid time");
  INPUT_INT( "ra_prefix_ptime", ra_prefix_ptime, "Prefix preferred time");
  add("<br />");
  SEND_STRING(&s->sout, buf);
  reset_buf();
  add("<br /><h3>RA Route Information</h3>");
  INPUT_FLAG_CB( "ra_rio_en", ra_rio_flags, CETIC_6LBR_MODE_SEND_RIO, "Include RIO");
  INPUT_INT( "ra_rio_lifetime", ra_rio_lifetime, "Route lifetime");
  add("<br />");
  SEND_STRING(&s->sout, buf);
  reset_buf();
#endif

#if UIP_CONF_IPV6_RPL && (CETIC_6LBR_ROUTER || CETIC_6LBR_SMARTBRIDGE)
  add("<br /><h2>RPL Configuration</h2>");
  INPUT_INT( "rpl_instance_id", rpl_instance_id, "Instance ID");
  INPUT_INT( "rpl_preference", rpl_preference, "Preference");
  INPUT_INT( "rpl_dio_intdoubl", rpl_dio_intdoubl, "DIO interval doubling");
  INPUT_INT( "rpl_dio_intmin", rpl_dio_intmin, "DIO min interval");
  SEND_STRING(&s->sout, buf);
  reset_buf();
  INPUT_INT( "rpl_dio_redundancy", rpl_dio_redundancy, "DIO redundancy");
  INPUT_INT( "rpl_min_hoprankinc", rpl_min_hoprankinc, "Min rank increment");
  INPUT_INT( "rpl_default_lifetime", rpl_default_lifetime, "Route lifetime");
  INPUT_INT( "rpl_lifetime_unit", rpl_lifetime_unit, "Route lifetime unit");
  SEND_STRING(&s->sout, buf);
  reset_buf();
#endif

#if CETIC_6LBR_ROUTER
//  add("<br /><h2>Packet filtering</h2>");
  INPUT_FLAG("rewrite", mode, CETIC_MODE_REWRITE_ADDR_MASK, "Address rewrite", "enabled", "disabled");
#endif
  if ((nvm_data.global_flags & CETIC_GLOBAL_DISABLE_CONFIG) == 0) {
    add("<br /><input type=\"submit\" value=\"Submit\"/></form>");
  }
  SEND_STRING(&s->sout, buf);
  reset_buf();

#if WEBSERVER_CONF_FILESTATS
  static uint16_t numtimes;

  add("<br><i>This page sent %u times</i>", ++numtimes);
#endif

#if WEBSERVER_CONF_LOADTIME
  numticks = clock_time() - numticks + 1;
  add(" <i>(%u.%02u sec)</i>", numticks / CLOCK_SECOND,
      (100 * (numticks % CLOCK_SECOND) / CLOCK_SECOND));
#endif
  add("</div>");
  
  add_div_footer();
  SEND_STRING(&s->sout, buf);
  SEND_STRING(&s->sout, BOTTOM);

  PSOCK_END(&s->sout);
}
/*---------------------------------------------------------------------------*/
#define PRINT_UIP_STAT(name, text) add(text " : %d<br />", uip_stat.name)

#define PRINT_RPL_STAT(name, text) add(text " : %d<br />", rpl_stats.name)

static
PT_THREAD(generate_statistics(struct httpd_state *s))
{
#if BUF_USES_STACK
  char buf[BUF_SIZE];
#endif
  PSOCK_BEGIN(&s->sout);

  SEND_STRING(&s->sout, TOP);
  SEND_STRING(&s->sout, BODY);
  reset_buf();
  add_div_home("Statistics");
  add("<div id=\"left_home\"class=\"inner\">");
  SEND_STRING(&s->sout, buf);
  reset_buf();

  add("<h2>IP</h2>");
#if UIP_STATISTICS
  add("<h3>IP</h3>");
  SEND_STRING(&s->sout, buf);
  reset_buf();
  PRINT_UIP_STAT( ip.recv, "Received packets" );
  PRINT_UIP_STAT( ip.sent, "Sent packets" );
  PRINT_UIP_STAT( ip.forwarded, "forwarded packets" );
  PRINT_UIP_STAT( ip.drop, "Dropped packets" );
  SEND_STRING(&s->sout, buf);
  reset_buf();
  PRINT_UIP_STAT( ip.vhlerr, "Wrong IP version or header length" );
  PRINT_UIP_STAT( ip.fragerr, "Dropped IP fragments" );
  PRINT_UIP_STAT( ip.chkerr, "Checksum errors" );
  PRINT_UIP_STAT( ip.protoerr, "Unsupported protocol" );
  add("<br />");
  SEND_STRING(&s->sout, buf);
  reset_buf();

  add("<h3>ICMP</h3>");
  PRINT_UIP_STAT( icmp.recv, "Received packets" );
  PRINT_UIP_STAT( icmp.sent, "Sent packets" );
  PRINT_UIP_STAT( icmp.drop, "Dropped packets" );
  PRINT_UIP_STAT( icmp.typeerr, "Unsupported type" );
  PRINT_UIP_STAT( ip.chkerr, "Checksum errors" );
  add("<br />");
  SEND_STRING(&s->sout, buf);
  reset_buf();

#if UIP_TCP
  add("<h3>TCP</h3>");
  PRINT_UIP_STAT( tcp.recv, "Received packets" );
  PRINT_UIP_STAT( tcp.sent, "Sent packets" );
  PRINT_UIP_STAT( tcp.drop, "Dropped packets" );
  PRINT_UIP_STAT( tcp.chkerr, "Checksum errors" );
  SEND_STRING(&s->sout, buf);
  reset_buf();
  PRINT_UIP_STAT( tcp.ackerr, "Ack errors" );
  PRINT_UIP_STAT( tcp.rst, "Received RST" );
  PRINT_UIP_STAT( tcp.rexmit, "retransmitted segments" );
  PRINT_UIP_STAT( tcp.syndrop, "Dropped SYNs" );
  PRINT_UIP_STAT( tcp.synrst, "SYNs for closed ports" );
  add("<br />");
  SEND_STRING(&s->sout, buf);
  reset_buf();
#endif
#if UIP_UDP
  add("<h3>UDP</h3>");
  PRINT_UIP_STAT( udp.recv, "Received packets" );
  PRINT_UIP_STAT( udp.sent, "Sent packets" );
  PRINT_UIP_STAT( udp.drop, "Dropped packets" );
  PRINT_UIP_STAT( udp.chkerr, "Checksum errors" );
  add("<br />");
  SEND_STRING(&s->sout, buf);
  reset_buf();
#endif
  add("<h3>NDP</h3>");
  PRINT_UIP_STAT( nd6.recv, "Received packets" );
  PRINT_UIP_STAT( nd6.sent, "Sent packets" );
  PRINT_UIP_STAT( nd6.drop, "Dropped packets" );
  add("<br />");
  SEND_STRING(&s->sout, buf);
  reset_buf();
#else
  add("<h3>IP statistics are deactivated</h3>");
#endif
#if UIP_CONF_IPV6_RPL
  add("<h2>RPL</h2>");
#if RPL_CONF_STATS
  PRINT_RPL_STAT( mem_overflows, "Memory overflow");
  PRINT_RPL_STAT( local_repairs, "Local repairs");
  PRINT_RPL_STAT( global_repairs, "Global repairs");
  SEND_STRING(&s->sout, buf);
  reset_buf();
  PRINT_RPL_STAT( malformed_msgs, "Invalid packets");
  PRINT_RPL_STAT( resets, "DIO timer resets");
  PRINT_RPL_STAT( parent_switch, "Parent switch");
  SEND_STRING(&s->sout, buf);
  reset_buf();
  PRINT_RPL_STAT( forward_errors, "Forward errors");
  PRINT_RPL_STAT( loop_errors, "Loop errors");
  PRINT_RPL_STAT( loop_warnings, "Loop warnings");
  PRINT_RPL_STAT( root_repairs, "Root repairs");
  add("<br />");
  SEND_STRING(&s->sout, buf);
  reset_buf();
#else
  add("<h3>RPL statistics are deactivated</h3>");
#endif
#if NETSTACK_CONF_MAC == csma_driver
  add("<h2>CSMA</h2>");
  add("Allocated packets : %d<br />", csma_allocated_packets());
  add("Allocated neighbors : %d<br />", csma_allocated_neighbors());
  add("Packet overflow : %d<br />", packet_overflow);
  add("Neighbor overflow : %d<br />", neighbor_overflow);
//  add("Callback count : %d<br />", callback_count);
  add("<br />");
  SEND_STRING(&s->sout, buf);
  reset_buf();
#endif
#endif
  
  add("</div>");
  
  add_div_footer();
  SEND_STRING(&s->sout, buf);
  reset_buf();

  SEND_STRING(&s->sout, BOTTOM);
  PSOCK_END(&s->sout);
}
/*---------------------------------------------------------------------------*/
static
PT_THREAD(generate_admin(struct httpd_state *s))
{
#if BUF_USES_STACK
  char buf[BUF_SIZE];
#endif
  PSOCK_BEGIN(&s->sout);

  SEND_STRING(&s->sout, TOP);
  SEND_STRING(&s->sout, BODY);
  reset_buf();
  add_div_home("Administration");
  add("<div id=\"left_home\"class=\"inner\">");
  SEND_STRING(&s->sout, buf);
  reset_buf();

  add("<h2>Administration</h2>");
  add("<h3>Logs</h3>");
  add("<form action=\"log\" method=\"get\">");
  add("<input type=\"submit\" value=\"Show log file\"/></form><br />");
  add("<form action=\"err\" method=\"get\">");
  add("<input type=\"submit\" value=\"Show error log file\"/></form><br />");
  add("<form action=\"clear_log\" method=\"get\">");
  add("<input type=\"submit\" value=\"Clear log file\"/></form><br />");
  SEND_STRING(&s->sout, buf);
  reset_buf();
  add("<h3>Restart</h3>");
  add("<form action=\"restart\" method=\"get\">");
  add("<input type=\"submit\" value=\"Restart 6LBR\"/></form><br />");
  add("<form action=\"reboot\" method=\"get\">");
  add("<input type=\"submit\" value=\"Reboot 6LBR\"/></form><br />");

  SEND_STRING(&s->sout, buf);
  reset_buf();
  add("<form action=\"halt\" method=\"get\">");
  add("<input type=\"submit\" value=\"Halt 6LBR\"/></form><br />");
  add("<h3>Configuration</h3>");
  add("<form action=\"reset_config\" method=\"get\">");
  add("<input type=\"submit\" value=\"Reset Config to factory default\"/></form><br />");

  SEND_STRING(&s->sout, buf);
  reset_buf();
  
  add("</div>");
  
  add_div_footer();
  SEND_STRING(&s->sout, buf);
  reset_buf();

  SEND_STRING(&s->sout, BOTTOM);
  PSOCK_END(&s->sout);
}
/*---------------------------------------------------------------------------*/
static
PT_THREAD(generate_restart_page(struct httpd_state *s))
{
#if BUF_USES_STACK
  char buf[BUF_SIZE];
#endif
  PSOCK_BEGIN(&s->sout);

  SEND_STRING(&s->sout, TOP);
  SEND_STRING(&s->sout,
              "<meta http-equiv=\"refresh\" content=\"2; url=/index.html\" />");
  SEND_STRING(&s->sout, BODY);
  reset_buf();
  switch (cetic_6lbr_restart_type) {
  case CETIC_6LBR_NO_RESTART:
    add_div_home("Done");
    break;
    case CETIC_6LBR_RESTART:
      add_div_home("Restart");
      break;
    case CETIC_6LBR_REBOOT:
      add_div_home("Reboot");
      break;
    case CETIC_6LBR_HALT:
      add_div_home("Halt");
      break;
    default:
      add_div_home("Error");
  }
  add("<div id=\"left_home\"class=\"inner\">");
  switch (cetic_6lbr_restart_type) {
    case CETIC_6LBR_NO_RESTART:
      add("Action done<br />");
      break;
    case CETIC_6LBR_RESTART:
      add("Restarting BR...<br />");
      break;
    case CETIC_6LBR_REBOOT:
      add("Rebooting BR...<br />");
      break;
    case CETIC_6LBR_HALT:
      add("Halting BR...<br />");
      break;
    default:
      add("Error...<br />");
  }
  add
    ("<a href=\"/config.html\">Click here if the page is not refreshing</a><br /><br />");
  add("</div>");
  
  add_div_footer();
  SEND_STRING(&s->sout, buf);
  reset_buf();

  SEND_STRING(&s->sout, BOTTOM);

  if ( cetic_6lbr_restart_type != CETIC_6LBR_NO_RESTART) {
    process_post_synch(&cetic_6lbr_process, cetic_6lbr_event, NULL);
  }

  PSOCK_END(&s->sout);
}
/*---------------------------------------------------------------------------*/
static
PT_THREAD(generate_404(struct httpd_state *s))
{
#if BUF_USES_STACK
  char buf[BUF_SIZE];
#endif
  PSOCK_BEGIN(&s->sout);

  SEND_STRING(&s->sout, TOP);
  SEND_STRING(&s->sout, BODY);
  reset_buf();
  add_div_home("404");
  add("<div id=\"left_home\"class=\"inner\">");
  add("404 : Page not found<br />");
  
  add("</div>");
  
  add_div_footer();
  SEND_STRING(&s->sout, buf);
  reset_buf();

  SEND_STRING(&s->sout, BOTTOM);
  PSOCK_END(&s->sout);
}
/*---------------------------------------------------------------------------*/
int
update_config(const char *name)
{
  const char *ptr = name;
  char *next;
  uint8_t reboot_needed = 0;
  uint8_t do_update = 1;
  uip_ipaddr_t loc_fipaddr;

  while(*ptr) {
    const char *param = ptr;

    next = strchr(ptr, '=');    //@mcroal:#
    if(!next)
      break;
    *next = 0;
    ptr = next + 1;
    const char *value = ptr;

    next = strchr(ptr, '&');   //@mcroal:#
    if(next) {
      *next = 0;
      ptr = next + 1;
    } else {
      ptr += strlen(ptr);
    }

//    printf("Got param: '%s' = '%s'\n", param, value);
    if(strcmp(param, "wait_ra") == 0) {
      if(strcmp(value, "0") == 0) {
        nvm_data.mode &= ~CETIC_MODE_WAIT_RA_MASK;
        reboot_needed = 1;
      } else if(strcmp(value, "1") == 0) {
        nvm_data.mode |= CETIC_MODE_WAIT_RA_MASK;
        reboot_needed = 1;
      } else {
        do_update = 0;
      }
    } else if(strcmp(param, "channel") == 0) {
      nvm_data.channel = atoi(value);
      reboot_needed = 1;
    } else if(strcmp(param, "wsn_pre") == 0) {
      if(uiplib_ipaddrconv(value, &loc_fipaddr)) {
        memcpy(&nvm_data.wsn_net_prefix, &loc_fipaddr.u8,
               sizeof(nvm_data.wsn_net_prefix));
        reboot_needed = 1;
      } else {
        do_update = 0;
      }
    } else if(strcmp(param, "wsn_auto") == 0) {
      if(strcmp(value, "0") == 0) {
        nvm_data.mode &= ~CETIC_MODE_WSN_AUTOCONF;
        reboot_needed = 1;
      } else if(strcmp(value, "1") == 0) {
        nvm_data.mode |= CETIC_MODE_WSN_AUTOCONF;
        reboot_needed = 1;
      } else {
        do_update = 0;
      }
    } else if(strcmp(param, "wsn_addr") == 0) {
      if(uiplib_ipaddrconv(value, &loc_fipaddr)) {
        memcpy(&nvm_data.wsn_ip_addr, &loc_fipaddr.u8,
               sizeof(nvm_data.wsn_ip_addr));
        reboot_needed = 1;
      } else {
        do_update = 0;
      }
    } else if(strcmp(param, "eth_pre") == 0) {
      if(uiplib_ipaddrconv(value, &loc_fipaddr)) {
        memcpy(&nvm_data.eth_net_prefix, &loc_fipaddr.u8,
               sizeof(nvm_data.eth_net_prefix));
        reboot_needed = 1;
      } else {
        do_update = 0;
      }
    } else if(strcmp(param, "eth_auto") == 0) {
      if(strcmp(value, "0") == 0) {
        nvm_data.mode &= ~CETIC_MODE_ETH_AUTOCONF;
        reboot_needed = 1;
      } else if(strcmp(value, "1") == 0) {
        nvm_data.mode |= CETIC_MODE_ETH_AUTOCONF;
        reboot_needed = 1;
      } else {
        do_update = 0;
      }
    } else if(strcmp(param, "eth_addr") == 0) {
      if(uiplib_ipaddrconv(value, &loc_fipaddr)) {
        memcpy(&nvm_data.eth_ip_addr, &loc_fipaddr.u8,
               sizeof(nvm_data.eth_ip_addr));
        reboot_needed = 1;
      } else {
        do_update = 0;
      }
    } else if(strcmp(param, "eth_dft") == 0) {
      if(uiplib_ipaddrconv(value, &loc_fipaddr)) {
        memcpy(&nvm_data.eth_dft_router, &loc_fipaddr.u8,
               sizeof(nvm_data.eth_dft_router));
        reboot_needed = 1;
      } else {
        do_update = 0;
      }
    } else if(strcmp(param, "rewrite") == 0) {
      if(strcmp(value, "0") == 0) {
        nvm_data.mode &= ~CETIC_MODE_REWRITE_ADDR_MASK;
      } else if(strcmp(value, "1") == 0) {
        nvm_data.mode |= CETIC_MODE_REWRITE_ADDR_MASK;
      } else {
        do_update = 0;
      }
    }
  }
  if(do_update) {
    store_nvm_config();
  }
  return !reboot_needed;
}
/*---------------------------------------------------------------------------*/
httpd_simple_script_t
httpd_simple_get_script(const char *name)
{
  static uip_ds6_route_t *route;
  static uip_ds6_nbr_t *neighbor;
  static uip_ipaddr_t ipaddr;

  redirect = 0;

  int admin = (nvm_data.global_flags & CETIC_GLOBAL_DISABLE_CONFIG) == 0;

  if(strcmp(name, "index.html") == 0 || strcmp(name, "") == 0) {
    return generate_index;
  } else if(strcmp(name, "sensors.html") == 0) {
    return generate_sensors;
  } else if(strcmp(name, "rpl.html") == 0) {
    return generate_rpl;
  } else if(strcmp(name, "network.html") == 0) {
    return generate_network;
  } else if(strcmp(name, "config.html") == 0) {
    return generate_config;
  } else if(strcmp(name, "statistics.html") == 0) {
    return generate_statistics;
#if UIP_CONF_IPV6_RPL
  } else if(admin && strncmp(name, "rpl-gr", 6) == 0) {
    rpl_repair_root(RPL_DEFAULT_INSTANCE);
    return generate_restart_page;
  } else if(admin && strncmp(name, "rpl-reset", 9) == 0) {
    rpl_reset_dio_timer(rpl_get_instance(RPL_DEFAULT_INSTANCE));
    return generate_restart_page;
  } else if(admin && strncmp(name, "rpl-child", 9) == 0) {
    uip_ipaddr_t addr;
    uip_create_linklocal_rplnodes_mcast(&addr);
    dis_output(&addr);
    return generate_restart_page;
#endif
  } else if(admin && memcmp(name, "route_rm", 8) == 0) {
    redirect = 1;
    if(uiplib_ipaddrconv(name + 9, &ipaddr) != 0) {
      route = uip_ds6_route_lookup(&ipaddr);
      if(route) {
        uip_ds6_route_rm(route);
      }
    }
    return generate_network;
  } else if(admin && memcmp(name, "nbr_rm", 6) == 0) {
    redirect = 1;
    if(uiplib_ipaddrconv(name + 7, &ipaddr) != 0) {
      neighbor = uip_ds6_nbr_lookup(&ipaddr);
      if (neighbor) {
        uip_ds6_nbr_rm(neighbor);
      }
    }
    return generate_network;
  } else if(admin && memcmp(name, "config?", 7) == 0) {
    if(update_config(name + 7)) {
      return generate_config;
    } else {
      cetic_6lbr_restart_type = CETIC_6LBR_RESTART;
      return generate_restart_page;
    }
  } else if(admin && strcmp(name, "admin.html") == 0) {
    return generate_admin;
  } else if(admin && memcmp(name, "reset_config", 12) == 0) {
    check_nvm(&nvm_data, 1);
    cetic_6lbr_restart_type = CETIC_6LBR_RESTART;
    return generate_restart_page;
  } else if(memcmp(name, "restart", 7) == 0) {
    cetic_6lbr_restart_type = CETIC_6LBR_RESTART;
    return generate_restart_page;
  } else if(memcmp(name, "reboot", 6) == 0) {
    cetic_6lbr_restart_type = CETIC_6LBR_REBOOT;
    return generate_restart_page;
  } else if(memcmp(name, "halt", 4) == 0) {
    cetic_6lbr_restart_type = CETIC_6LBR_HALT;
    return generate_restart_page;
//#if CONTIKI_TARGET_NATIVE
//  } else if (access(filename, R_OK) == 0) {
//    return send_file;
//#endif
  } else {
    return generate_404;
  }
}
/*---------------------------------------------------------------------------*/
void
add_div_home(char const *title)
{
  add("<div id=\"intro_home\"class=\"inner\">%s</div>", title);
}
/*---------------------------------------------------------------------------*/
static void
add_div_footer()
{
  add("</div><div id=\"footer\"class=\"inner\">6lbr maintained by ofc-6lbr</div>");
}
/*---------------------------------------------------------------------------*/
static void
add_network_cases(const uint8_t state)
{
  switch (state) {
  case NBR_INCOMPLETE:
    add("INCOMPLETE");
    break;
  case NBR_REACHABLE:
    add("REACHABLE");
    break;
  case NBR_STALE:
    add("STALE");
    break;
  case NBR_DELAY:
    add("DELAY");
    break;
  case NBR_PROBE:
    add("NBR_PROBE");
    break;
  }
}
/*---------------------------------------------------------------------------*/
/*Macro redefined : RESET_BUF()*/
/*---------------------------------------------------------------------------*/
static void
reset_buf()
{
#if BUF_USES_STACK
  bufptr = buf;
  bufend = bufptr + sizeof(buf);
#else
  blen = 0;
#endif
}
/*---------------------------------------------------------------------------*/
/*Macro redefined : ADD()*/
/*---------------------------------------------------------------------------*/
static void
add(char *str, ...)
{
  va_list arg;

  va_start(arg, str);
  //ADD(str, arg); //TODO : bug while formating
#if BUF_USES_STACK
  bufptr += vsnprintf(bufptr, bufend - bufptr, str, arg);
#else
  blen += vsnprintf(&buf[blen], sizeof(buf) - blen, str, arg);
#endif
  va_end(arg);
}
/*---------------------------------------------------------------------------*/
