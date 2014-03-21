/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

void copy_mac_addr(uint8_t* dest, uint8_t* source) {
  memcpy(dest, source, ETHER_ADDR_LEN);
}

void swap_ip_addr(uint32_t* ip1, uint32_t* ip2) {
  uint32_t temp = (*ip1);
  (*ip1) = (*ip2);
  (*ip2) = temp;
}
/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    print_hdrs(packet, len);

    int minLength = sizeof(sr_ethernet_hdr_t);
    int offset = 0;

    /* Check if ethernet header valid length */
    if(len < minLength) {
      fprintf(stderr, "*** -> Invalid Length\n");
      return;
    }

    uint16_t ethtype = ethertype(packet);
    if (ethtype == ethertype_ip) {
        return;
    }

    /* ARP PACKET */
    if(ethtype == ethertype_arp) {
        minLength += sizeof(sr_arp_hdr_t);

        /* Check valid length */
        if(len < minLength) {
          fprintf(stderr, "*** -> Invalid Length\n");
          return;
        }

        offset += sizeof(sr_ethernet_hdr_t);
        sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + offset);

        /* Process arp REQUEST */
        if(ntohs(arp_hdr->ar_op) == arp_op_request) {
          printf("REQUEST");
          struct sr_if* iface;
          iface = sr_get_interface(sr, interface);
          if(iface == 0)
            return;
          if((iface->ip) == (arp_hdr->ar_tip)){
            uint8_t* reply = (uint8_t*)malloc(len);
            memcpy(reply, packet, len);

            /* Format ethernet frame */
            sr_ethernet_hdr_t* reply_eth = (sr_ethernet_hdr_t*) reply;
            copy_mac_addr(reply_eth->ether_dhost, reply_eth->ether_shost);
            copy_mac_addr(reply_eth->ether_shost, iface->addr);

            /* Format arp header */
            sr_arp_hdr_t* reply_arp = (sr_arp_hdr_t*)(reply + offset);
            reply_arp->ar_op = htons(arp_op_reply);
            swap_ip_addr(&(reply_arp->ar_sip), &(reply_arp->ar_tip));
            copy_mac_addr(reply_arp->ar_tha, reply_arp->ar_sha);
            copy_mac_addr(reply_arp->ar_sha, iface->addr);

            print_hdrs(reply, len);

            sr_send_packet(sr, reply, len, interface);
            return;
          }
          else
            return;
        }
        /* Process arp REPLY */
        else if(ntohs(arp_hdr->ar_op) == arp_op_reply) {
          printf("REPLY");
        }
        else {
          fprintf(stderr, "*** -> Invalid ARP");
          return;
        }
        return;
    }

    /* IP PACKET */
    if(ethtype == ethertype_ip) {
        minLength += sizeof(sr_ip_hdr_t);

        /* Check valid length */
        if(len < minLength) {
          fprintf(stderr, "*** -> Invalid Length\n");
          return;
        }
    }

}/* end sr_ForwardPacket */

