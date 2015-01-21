#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#include <string.h>

#include "dev/watchdog.h"
#include "net/rpl/rpl.h"
#include "ip64.h"
#include "ip64-addr.h"
#include "ip64-addrmap.h"
#include "bsp.h"

#define DEBUG DEBUG_NONE
#include "uip-debug.h"

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])

#define MAX_PAYLOAD_LEN 10

static struct uip_udp_conn *server_conn;
static char buf[MAX_PAYLOAD_LEN];
static uint16_t len;
/*---------------------------------------------------------------------------*/
PROCESS(ip64_server_process, "ip64 server");
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  memset(buf, 0, MAX_PAYLOAD_LEN);
  if(uip_newdata()) {    
    len = uip_datalen();
    memcpy(buf, uip_appdata, len);
    if(buf[0] == 'A') {
      if(buf[1] == 'a') {
        /* @mcroal:check the ipv6 address */
        PRINTF("give a ipv4 address for :");
        PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
        struct ip64_addrmap_entry *m;
        uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);
        m = ip64_addrmap_lookup(&server_conn->ripaddr, NULL);
        if(m == NULL) {
          m = ip64_addrmap_create(&server_conn->ripaddr);          
          if(m == NULL) {               
            PRINTF("Could not create new map\n");  
            return;            
          } 
        }
        server_conn->rport = UIP_UDP_BUF->srcport;
        memcpy(&buf[2], m->ip4addr.u8, 4);
        uip_udp_packet_send(server_conn, buf, 6);
        /* Restore server connection to allow data from any node */
        uip_create_unspecified(&server_conn->ripaddr);
        server_conn->rport = 0;
      }
    } 
    memset(buf, 0, MAX_PAYLOAD_LEN);
  }
  return;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(ip64_server_process, ev, data)
{
  PROCESS_BEGIN();
 
  /* @mcroal:Listen this port and confige ipv4 address for a node. */
  server_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(server_conn, UIP_HTONS(3000));
  PRINTF("Listen port: 3000, TTL=%u\n", server_conn->ttl);
  
  while(1) {
    PROCESS_WAIT_EVENT();
    if(ev == tcpip_event) {
      tcpip_handler();
    }
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
