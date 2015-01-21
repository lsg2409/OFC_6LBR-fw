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
#include "ip64-addrmap.h"

#include "lib/memb.h"
#include "lib/list.h"

#include "ip64.h"

#include <string.h>

#define MAX_AGE (CLOCK_SECOND * 60 * 50)     //@mcroal fifty minute

#ifdef IP64_ADDRMAP_CONF_ENTRIES
#define NUM_ENTRIES IP64_ADDRMAP_CONF_ENTRIES
#else /* IP64_ADDRMAP_CONF_ENTRIES */
#define NUM_ENTRIES 32
#endif /* IP64_ADDRMAP_CONF_ENTRIES */

MEMB(entrymemb, struct ip64_addrmap_entry, NUM_ENTRIES);
LIST(entrylist);

uip_ip4addr_t mapaddr;

#define printf(...)

/*---------------------------------------------------------------------------*/
struct ip64_addrmap_entry *
ip64_addrmap_list(void)
{
  return list_head(entrylist);
}
/*---------------------------------------------------------------------------*/
void
ip64_addrmap_init(void)
{
  memb_init(&entrymemb);
  list_init(entrylist);
}
/*---------------------------------------------------------------------------*/
static void
check_age(void)
{
  struct ip64_addrmap_entry *m;

  /* Walk through the list of address mappings, throw away the ones
     that are too old. */
  m = list_head(entrylist);
  while(m != NULL) {
    if(timer_expired(&m->timer)) {
      list_remove(entrylist, m);
      memb_free(&entrymemb, m);
      m = list_head(entrylist);
    } else {
      m = list_item_next(m);
    }
  }
}
/*---------------------------------------------------------------------------*/
struct ip64_addrmap_entry *
ip64_addrmap_lookup(const uip_ip6addr_t *ip6addr,
		    const uip_ip4addr_t *ip4addr)
{
  struct ip64_addrmap_entry *m;

  check_age();
  if(ip6addr != NULL)
  {
    /* @mcroal:lookup a IPv4 address */
    for(m = list_head(entrylist); m != NULL; m = list_item_next(m)) {
      if(uip_ip6addr_cmp(&m->ip6addr, ip6addr)) {
        timer_set(&m->timer, MAX_AGE);
        return m;
      }
    }
  } else if(ip4addr != NULL) {
    /* @mcroal:lookup a IPv6 address */
      for(m = list_head(entrylist); m != NULL; m = list_item_next(m)) {
      if(uip_ip4addr_cmp(&m->ip4addr, ip4addr)) {
        timer_set(&m->timer, MAX_AGE);
        return m;
      }
    }
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
uip_ip4addr_t *
set_mapped_addr(void)
{  
  /* @mcroal: increase ipv4 address for a new mapentry */  
  uip_ip4addr_copy(&mapaddr, ip64_get_draddr());
  (&mapaddr)->u8[3] = (&mapaddr)->u8[3] + (uint8_t)list_length(entrylist) + 1; 
  return &mapaddr;
}
/*---------------------------------------------------------------------------*/
struct ip64_addrmap_entry *
ip64_addrmap_create(const uip_ip6addr_t *ip6addr)
{
  struct ip64_addrmap_entry *m;

  check_age();
  m = memb_alloc(&entrymemb);
  if(m != NULL) {
    uip_ip4addr_copy(&m->ip4addr, set_mapped_addr());
    uip_ip6addr_copy(&m->ip6addr, ip6addr);
    timer_set(&m->timer, MAX_AGE);

    list_add(entrylist, m);
    return m;
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
