/*
 * Copyright (c) 2006-2016 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

/*
modification history
--------------------
01dec16,wfl  fix ping fail for certain types of addresses (V7NET-1182)
23aug16,kjn  The ACD (address collision detection) mechanism must never remove
             assigned IP-addresses when then feature is not used.
26aug16,wfl  fix fragmented packet hdr->id incorrect (V7NET-909)
25aug16,rjq  ping with don't fragment flag set fragments packet. (V7NET-907)
18aug16,ljl  Add a configure option for ipv4 random id. (V7NET-898)
25jun16,h_x  Port TSR defect fix forward from vxworks6.9 into vx7. (F6988)
17jun16,ljl  Add random in incrementing IP identification.
05may16,ljl  Relative IP identification number change. (V7NET-803)
27apr16,rjq  Support ipnet strict mode. (US77183)
29feb16,rjq  Broadcast packets should not be forwarded. (V7NET-771)
21jan16,dlk  Rework V7NET-727 temporary fix.
12jan16,ghl  Modify the conditions that create a rx dst cache. (V7NET-727)
28oct15,wfl  Added address event user-defined hook for V7NET-666
06feb15,zan  Replace static with IP_STATIC for function. 
18aug14,jxy  static analysis issues cleanup, V7NET-442
21arp14,h_x  remove mip US35691
*/

/*
 ****************************************************************************
 * 1                    DESCRIPTION
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 2                    CONFIGURATION
 ****************************************************************************
 */

#ifndef IPCOM_KERNEL
#define IPCOM_KERNEL
#endif
#include "ipnet_config.h"

/*
 *===========================================================================
 *                         misc
 *===========================================================================
#define IPCOM_USE_PROFILING_ENABLE
 */

/*
 ****************************************************************************
 * 3                    INCLUDE FILES
 ****************************************************************************
 */

#ifdef IPCOM_USE_INET

#define IPCOM_USE_CLIB_PROTO
#include <ipcom_clib.h>
#include <ipcom_cstyle.h>
#include <ipcom_err.h>
#include <ipcom_inet.h>
#include <ipcom_prof.h>
#include <ipcom_syslog.h>
#include <ipcom_sysvar.h>
#include <ipcom_type.h>
#include <ipcom_hash.h>


#include "ipnet.h"
#include "ipnet_dst_cache.h"
#include "ipnet_eth.h"
#include "ipnet_h.h"
#include "ipnet_ip4.h"
#include "ipnet_loopback.h"
#include "ipnet_neigh.h"
#include "ipnet_peer_info.h"

#ifdef IPTCP
#include <iptcp.h>
#endif

#ifdef IPSCTP
#include <ipsctp.h>
#endif
#ifdef IPIPSEC2
#include <ipipsec.h>
#endif

#ifdef IPNET_USE_ROUTESOCK
#include "ipnet_routesock.h"
#endif

#ifdef IPNET_USE_NETLINK
#include "ipnet_netlink_h.h"
#include "ipnet_rtnetlink_h.h"
#endif

#ifdef IPNET_USE_TUNNEL
#include "ipnet_tunnel.h"
#endif

#ifdef IPNET_USE_VRRP
#include "ipnet_vrrp.h"
#endif

#ifdef IPFIREWALL
#include <ipfirewall.h>
#include <ipfirewall_h.h>
#endif

#ifdef IPROHC
#include <iprohc.h>
#endif

#ifdef IPCOM_WV_INSTRUMENTATION
#include <ipcom_windview.h>
#endif

#ifdef IPCOM_USE_FORWARDER
#include <ipcom_forwarder.h>
#endif

#ifdef IPBRIDGE
#include "ipbridge.h"
#endif
#include <ipaddrEventLib.h>

/*
 ****************************************************************************
 * 4                    DEFINES
 ****************************************************************************
 */

/* Maximum number of bytes of original IP datagram to send in ICMP error reply. */
#define IPNET_ICMP_MAX_SIZE    256  /* enough to handle tunnels better. */

/*
 *===========================================================================
 *                         misc
 *===========================================================================
 */

#define IPNET_ICMP_HDR_SIZE    (8)


/*
 *===========================================================================
 *                         ICMP for IPv4
 *===========================================================================
 */
#define IPNET_ICMP4_TYPE_ECHO_REPLY            0
#define IPNET_ICMP4_TYPE_DST_UNREACHABLE       3
#define IPNET_ICMP4_TYPE_SOURCEQUENCH          4
#define IPNET_ICMP4_TYPE_REDIRECT              5
#define IPNET_ICMP4_TYPE_ECHO_REQUEST          8
#define IPNET_ICMP4_TYPE_ROUTER_ADVERT         9
#define IPNET_ICMP4_TYPE_ROUTER_SOLICIT       10
#define IPNET_ICMP4_TYPE_TIME_EXCEEDED        11
#define IPNET_ICMP4_TYPE_PARAMPROB            12
#define IPNET_ICMP4_TYPE_TSTAMP_REQUEST       13
#define IPNET_ICMP4_TYPE_TSTAMP_REPLY         14
#define IPNET_ICMP4_TYPE_MASK_REQUEST         17
#define IPNET_ICMP4_TYPE_MASK_REPLY           18

/* [3] Destination unreachable codes */
#define IPNET_ICMP4_CODE_DST_UNREACH_NET      0  /* Network Unreachable */
#define IPNET_ICMP4_CODE_DST_UNREACH_HOST     1  /* Host Unreachable */
#define IPNET_ICMP4_CODE_DST_UNREACH_PROTO    2  /* Protocol Unreachable */
#define IPNET_ICMP4_CODE_DST_UNREACH_PORT     3  /* Port Unreachable */
#define IPNET_ICMP4_CODE_DST_NEEDFRAG         4  /* Fragmentation needed but no frag. bit set */
#define IPNET_ICMP4_CODE_DST_SRCFAIL          5  /* Source routing failed */
#define IPNET_ICMP4_CODE_DST_PROHIBITED_NET   9  /* Destination network administratively prohibited */
#define IPNET_ICMP4_CODE_DST_PROHIBITED_HOST 10  /* Destination host administratively prohibited */
#define IPNET_ICMP4_CODE_DST_PROHIBITED_ADM  13  /* Communication Administratively Prohibited */

/* [5] Redirect codes */
#define IPNET_ICMP4_CODE_RED_NETWORK          0
#define IPNET_ICMP4_CODE_RED_HOST             1
#define IPNET_ICMP4_CODE_RED_TOS_AND_NETWORK  2
#define IPNET_ICMP4_CODE_DST_TOS_AND_HOST     3

/* [11] Time exceeded codes */
#define IPNET_ICMP4_CODE_TIM_TTL              0
#define IPNET_ICMP4_CODE_TIM_REASSEMBLY       1

/*
 * TOS to use for Destination Unreachable, Redirect, Time Exceeded,
 * and Parameter Problem
 */
#define IPNET_ICMP4_TOS_INTERNETWORK_CONTROL  6

/*
 * RFC 3376 state that TOS of all IGMPv3 messages must be 0xc0
 * and that they must include the router alert option.
 */
#define IPNET_IGMPV3_TOS 0xc0


/*
 *===========================================================================
 *                         IGMP for IPv4
 *===========================================================================
 */

/* IGMP version 1 is defined in RFC 1112 */
/* IGMP version 2 is defined in RFC 2236 */
/* IGMP version 3 is defined in RFC 3376 */
#define IPNET_IGMP4_TYPE_MEMBERSHIP_QUERY      0x11
#define IPNET_IGMP4_TYPE_V1_MEMBERSHIP_REPORT  0x12
#define IPNET_IGMP4_TYPE_V2_MEMBERSHIP_REPORT  0x16
#define IPNET_IGMP4_TYPE_V2_LEAVE_GROUP        0x17
#define IPNET_IGMP4_TYPE_V3_MEMBERSHIP_REPORT  0x22

/* The interface is running on a link with at least one IGMPv1 host/router */
#define IPNET_IGMPV1_MODE   1
/* The interface is running on a link with at least one IGMPv2 host/router */
#define IPNET_IGMPV2_MODE   2
/* The interface is running in IGMPv3 mode */
#define IPNET_IGMPV3_MODE   3

#if defined(IPNET_USE_RFC3927) || defined(IPNET_USE_RFC5227)
/* Address Conflict Detection state machine */
/*
                                                <- defended -
                                               |            ^
                                               |            |
     DISABLED -> INIT -> PROBE -> ANNOUNCE -> ACTIVE -> DEFEND
                  ^        |         |           |        |
                  |        |         |           |        |
                  \        /         /           /        /
                   - duplicate <----- <---------- <-------
*/
#define IPNET_IP4_ACD_STATE_DISABLED 0  /* Address Conflict Detection disabled */
#define IPNET_IP4_ACD_STATE_INIT     1  /* Start adress conflict detection */
#define IPNET_IP4_ACD_STATE_PROBE    2  /* Check if another host has the address */
#define IPNET_IP4_ACD_STATE_DEFEND   3  /* Detected another host using the same address
                                           try to make this host the sole owner of it */
#define IPNET_IP4_ACD_STATE_ANNOUNCE 4  /* Update the ARP cache of all hosts,
                                           address assigned to interface */
#define IPNET_IP4_ACD_STATE_ACTIVE   5  /* Address is in use */
#define IPNET_IP4_ACD_STATE_MAX      5
#endif /* defined(IPNET_USE_RFC3927) || defined(IPNET_USE_RFC5227) */

/*
 ****************************************************************************
 * 5                    TYPES
 ****************************************************************************
 */

/* Search key for IPv4 addresses */
typedef struct Ipnet_ip4_addr_lookup_struct
{
    Ip_u32            ifindex;
    struct Ip_in_addr addr;
    Ip_u16            vr;
}
Ipnet_ip4_addr_lookup;

/* Information needed to process redirect messages */
struct Ipnet_icmp4_redirect_foreach
{
    /* Egress interface index to reach 'target' */
    Ip_u32            ifindex;

    /* Redirect sender IP-address */
    struct Ip_in_addr src;

    /*
     * Destination IP address in the message that caused
     * the redirect.
     */
    struct Ip_in_addr target;

    /*
     * Address of the new first hop. Might be equal to 'target' if
     * that node is directly reachable
     */
    struct Ip_in_addr new_first_hop;
};


/* IGMPv3 report callback */
struct Ipnet_igmpv3_report_for_each_data
{
    Ipnet_ip4_addr_entry          *addr_entry;
    Ipnet_pkt_igmpv3_group_record *group_record;
    Ipcom_pkt                     *pkt;
    Ipcom_set                     *set;
};


/*
 *===========================================================================
 *                     Ipnet_ip4_layer_info
 *===========================================================================
 * This structure holds information that is only valid while the
 * call stack has not exited the IPv4 layer.
 *
 */
typedef struct Ipnet_ip4_layer_info_struct
{
    Ip_u8                       proto;      /* IP protcol */
    Ip_u8                       ttl;        /* Time to live */
    Ip_u8                       flags;      /* IPNET_IP4_OPF_xxx flags */
    Ip_u32                      id;         /* Identification. */

    Ip_u16                     *chksum_ptr; /* Pointer to where the
                                               checksum should be
                                               written or IP_NULL */
    Ipnet_neigh                *nexthop;    /* Pointer to the neighbor
                                               entry of the next hop
                                               or IP_NULL if the stack
                                               should find the best
                                               next hop */
    struct Ipnet_ip4_sock_opts *opts;       /* IP options that should
                                               be addded */
}
Ipnet_ip4_layer_info;

#define IPNET_IP4_LAYER_SET_ID(l, ip4_id)   \
    ((l)->id = 0xFFFF0000|ip4_id)

#define IPNET_IP4_LAYER_GET_ID(l)   \
    ((Ip_u16)((l)->id & 0x0000FFFF))


/*
 * Possible IPv4 layer information flags
 */
#define IPNET_IP4_OPF_ROUTER_ALERT (1 << 0) /* Router alert IP option
                                               should be added
                                               (egress) or is present
                                               (ingress). */
#define IPNET_IP4_OPF_DONT_FRAG    (1 << 1) /* Set the don't fragment
                                               bit in the IP header */
#define IPNET_IP4_OPF_NO_LOCAL_FRAG (1 << 2) /* Do not allow local
                                               fragmentation  */

/*
 * Macros to store/fetch IPv4 packet information to/from a packet
 */
#define IPNET_IP4_SET_LAYER_INFO(pkt, pinfo) \
    ((pkt)->link_cookie = (Ip_ptrdiff_t) pinfo)
#define IPNET_IP4_GET_LAYER_INFO(pkt) \
    ((Ipnet_ip4_layer_info *) (pkt)->link_cookie)


typedef struct Ipnet_ip4_opt_param_struct
{
    Ip_u32          seen_options;
    Ip_size_t       optend;
    Ip_size_t       optidx;
    Ip_size_t       optsize;
    char            options[40];
    Ip_bool         need_cksum;
    Ipnet_dst_cache *dst;
    Ipcom_pkt       *pkt;
    Ipnet_pkt_ip    *ip_hdr;
} Ipnet_ip4_opt_param_t;

typedef int (*Ipnet_ip4_opt_rx_func)(Ipnet_pkt_ip_opt *opt,
                                     Ipnet_ip4_opt_param_t *params);

/*
 ****************************************************************************
 * 6                    EXTERN PROTOTYPES
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 7                    LOCAL PROTOTYPES
 ****************************************************************************
 */

IP_STATIC int
ipnet_ip4_opt_ra_rx(Ipnet_pkt_ip_opt *opt,
                    Ipnet_ip4_opt_param_t *params);
IP_STATIC int
ipnet_ip4_opt_ts_rx(Ipnet_pkt_ip_opt *opt,
                    Ipnet_ip4_opt_param_t *params);

IP_STATIC int
ipnet_ip4_opt_unsupported_rx(Ipnet_pkt_ip_opt *opt,
                             Ipnet_ip4_opt_param_t *params);

IP_STATIC int
ipnet_ip4_opt_srr_rx(Ipnet_pkt_ip_opt *opt, Ipnet_ip4_opt_param_t *params);
IP_STATIC int
ipnet_ip4_opt_rr_rx(Ipnet_pkt_ip_opt *opt, Ipnet_ip4_opt_param_t *params);

IP_STATIC void
ipnet_ip4_reg_opt_rx(Ip_u8 opt, Ipnet_ip4_opt_rx_func func);

IP_STATIC int
ipnet_ip4_addr_init_neigh_for_arp(Ipnet_ip4_addr_entry *addr);

IP_STATIC int
ipnet_ip4_dst_cache_local_tx_ctor(Ipnet_dst_cache *dst,
                                  Ipnet_route_entry *rt);

IP_STATIC void *
ipnet_ip4_get_ip_opt_next(void *optprev, void *opts_ptr, int optlen);

#ifndef IPCOM_FORWARDER_NAE
IP_STATIC int
ipnet_ip4_deliver_to_raw_sock(Ipnet_dst_cache *dst,
                              Ipcom_pkt *pkt,
                              Ip_bool take_ownership_of_pkt);

IP_STATIC void
ipnet_igmp_input(Ipnet_dst_cache *dst, Ipcom_pkt *pkt);
#endif

#ifdef IPNET_USE_SOURCE_SPECIFIC_MCAST
IP_STATIC void
ipnet_igmpv3_create_membership_report(Ipcom_pkt *pkt, Ipnet_ip4_addr_entry *addr_entry);
#endif

#ifndef IPCOM_FORWARDER_NAE
IP_STATIC void
ipnet_igmp_report_general_query(Ipnet_ip4_addr_entry *addr_entry);

IP_STATIC void
ipnet_igmp_report_specific_query(Ipnet_ip4_addr_entry *addr_entry);

IP_STATIC Ip_bool
ipnet_icmp_and_igmp_is_sane(Ipcom_pkt *pkt);

IP_STATIC void
ipnet_icmp4_input(Ipnet_dst_cache *dst, Ipcom_pkt *pkt);

#endif

IP_STATIC void
ipnet_igmp_report_filter_change(Ipnet_ip4_addr_entry *addr_entry);

#ifdef IPNET_USE_RFC1256
IP_STATIC void ipnet_ip4_rfc1256_state_run(Ipnet_netif *netif);
IP_STATIC void ipnet_ip4_rfc1256_advertise_schedule(Ipnet_netif    *netif,
                                                    Ip_u32         tmo);
#endif


#if defined(IPNET_USE_RFC3927) || defined(IPNET_USE_RFC5227)
IP_STATIC void ipnet_ip4_acd_set_state(Ipnet_ip4_addr_entry *addr, Ip_u8 state);
IP_STATIC void ipnet_ip4_lladdr_init(Ipnet_netif *netif);
#endif

IP_GLOBAL struct Ip_sockaddr *
ipnet_ip4_addr_to_sockaddr(struct Ip_sockaddr_in *sin, Ip_u32 in_addr_n);

/*
 ****************************************************************************
 * 8                    DATA
 ****************************************************************************
 */

/*
 * Receive handlers for all possible IP protocols.
 */
static Ipnet_transport_layer_rx_func ipnet_ip4_transport_layer_rx[256];
static Ipnet_ip4_opt_rx_func ipnet_ip4_opts[256];

/*
 ****************************************************************************
 * 9                    STATIC FUNCTIONS
 ****************************************************************************
 */

IP_STATIC void
ipnet_ip4_get_ip_id(Ipnet_dst_cache  *dst,
                    Ipnet_ip4_layer_info    *ip4_layer,
                    Ip_u16                  *ip4_id)
{

    if (ipnet_shared()->conf.inet.random_ip_id)
    {
        Ip_u32 hash_val = ipcom_hash_update(&dst->laddr, sizeof(dst->laddr), ip4_layer->proto);
        Ip_u32 i = hash_val % IPNET_PEER_INFO_ID_CNT;
        
        *ip4_id = (Ip_u16) (ip4_layer->id
               ? IPNET_IP4_LAYER_GET_ID(ip4_layer)
               : ipcom_atomic_add_and_return(&dst->peer_info->ids[i], (Ip_u8)ipcom_rand() + 1));
    }
    else
    {
        *ip4_id = (Ip_u16) (ip4_layer->id
               ? IPNET_IP4_LAYER_GET_ID(ip4_layer)
               : ipcom_atomic_add_and_return(&dst->peer_info->id, 1));
    }
    
}


/*
 *===========================================================================
 *                      ipnet_ip4_flow_spec_from_pkt
 *===========================================================================
 * Description: Initializes the flow specification structure based on
 *              an IP datagram.
 * Parameters:  flow_spec - pointer to where the flow specification
 *                      should be stored.
 *              pkt - an IPCOM packet
 *              ip_hdr - pointer to the IP header within the packet.
 *              is_ingress - IP_TRUE if this is an ingress pkt,
 *                           IP_FALSE if this is an egress pkt
 * Returns:
 *
 */
IP_GLOBAL void
ipnet_ip4_flow_spec_from_pkt(Ipnet_flow_spec *flow_spec,
                             const Ipcom_pkt *pkt,
                             const Ipnet_pkt_ip *ip_hdr,
                             Ip_bool is_ingress)
{
    flow_spec->vr             = pkt->vr_index;
    flow_spec->flags          = 0;
    flow_spec->to.in.s_addr   = IPNET_IP4_GET_IPADDR((void *)ip_hdr->dst);
    flow_spec->from.in.s_addr = IPNET_IP4_GET_IPADDR((void *)ip_hdr->src);
    flow_spec->ds             = ip_hdr->tos;
    flow_spec->zone_id        = 0;
    if (is_ingress)
    {
        flow_spec->ingress_ifindex = pkt->ifindex;
        flow_spec->egress_ifindex  = 0;
    }
    else
    {
        flow_spec->ingress_ifindex = 0;
        flow_spec->egress_ifindex  = pkt->ifindex;
    }
}


/*
 *===========================================================================
 *                      ipnet_ip4_process_ts_opt
 *===========================================================================
 * Description: Processes the timestamp option
 * Parameters:  ts - The timestamp option buffer.
 *              dst_addr_n - The final destination.
 *              pkt - The packet that holds the option.
 *              is_ingress - IP_FALSE if this packet is about to be
 *                    transmitted, IP_TRUE otherwise
 * Returns:     0 = success, <0 = error code.
 *
 */
IP_STATIC int
ipnet_ip4_process_ts_opt(Ipnet_pkt_ip_opt_timestamp *ts,
                         Ip_u32 *dst_addr_n,
                         Ipcom_pkt *pkt,
                         Ip_bool is_ingress)
{
    int          ts_len;
    Ip_u32       timestamp;
    Ip_u16       vr = pkt->vr_index;

    switch (IPNET_OPT_TS_GET_FLAGS(ts))
    {
    case IP_IPOPT_TS_TSONLY:
        ts_len = 4;
        break;
    case IP_IPOPT_TS_TSANDADDR:
    case IP_IPOPT_TS_PRESPEC:
        ts_len = 8;
        break;
    default:
        /*
         * Unknown format, ignore this option
         */
        return 0;
    }

    if (ts->pointer < 5 || ((ts->pointer - 5) & (ts_len - 1)) != 0)
        /*
         * RFC791; the Pointer is the number of octets from the
         * beginning of this option to the end of timestamps plus one
         * (i.e., it points to the octet beginning the space for next
         * timestamp).  The smallest legal value is 5.
         */
        return IPNET_ERRNO(EINVAL);

    if (ts->pointer + ts_len > ts->len + 1)
    {
        if (ts->pointer <= ts->len)
            /*
             * RFC791; The timestamp area is full when the pointer
             * is greater than the length.
             */
            return IPNET_ERRNO(EINVAL);
        if (IPNET_OPT_TS_GET_OVERFLOW_COUNT(ts) == 0xf)
            return IPNET_ERRNO(ENOSPC);
        if (is_ingress)
            /*
             * The overflow count must only be increased 1 time per IP
             * module.
             */
            IPNET_OPT_TS_INC_OVERFLOW_COUNT(ts);
        return 0;
    }

    /*
     * RFC791, page 22; If the time is not available in milliseconds
     * or cannot be provided with respect to midnight UT then any time
     * may be inserted as a timestamp provided the high order bit of
     * the timestamp field is set to one to indicate the use of a
     * non-standard value.
     */
    timestamp = (Ip_u32)((ipnet_fetch_msec_now() % (1000 * 60 * 60 * 24)) | 0x80000000);

    switch (IPNET_OPT_TS_GET_FLAGS(ts))
    {
    case IP_IPOPT_TS_TSANDADDR:
        if (ipnet_ip4_get_addr_type(IP_GET_32ON16(dst_addr_n),
                                    vr,
                                    IP_NULL) != IPNET_ADDR_TYPE_NOT_LOCAL)
            /*
             * This is the final destination for this packet, use that
             * address in the timestamp option.
             */
            ipcom_memcpy(&ts->timestamp[ts->pointer - 5], dst_addr_n, 4);
        else
        {
            Ipnet_netif *netif = ipnet_if_indextonetif(vr, pkt->ifindex);
            if(IP_NULL == netif)
            {
                IPCOM_LOG0(ERR, "ipnet_ip4_process_ts_opt: netif is NULL, return!");
                return IPNET_ERRNO(EINVAL);
            }

            /*
             * This node are forwarding or transmitting this packet,
             * use the primary address of the egress interface as node
             * IP address in the option.
             */

            if (netif->inet4_addr_list == IP_NULL)
                return 0;

            ipcom_memcpy(&ts->timestamp[ts->pointer - 5],
                         &netif->inet4_addr_list->ipaddr_n,
                         4);
        }
        break;
    case IP_IPOPT_TS_PRESPEC:
        if (ipnet_ip4_get_addr_type(IP_GET_32ON8(&ts->timestamp[ts->pointer - 5]),
                                    vr,
                                    IP_NULL) == IPNET_ADDR_TYPE_NOT_LOCAL)
            return 0;
        break;
    default:
        break;
    }

    ts->pointer = (Ip_u8) (ts->pointer + ts_len);
    IP_SET_HTONL(&ts->timestamp[ts->pointer - 9], timestamp);
    return 0;
}


/*
 *===========================================================================
 *                     ipnet_ip4_srr_process_local_tx
 *===========================================================================
 * Description: Processes source route option
 * Parameters:  net - stack instance
 *              flow_specp - flow specification
 *              opt - pointer to the SSRR or LSRR option
 *              info - IPv4 specific context information
 * Returns:     Destination cache entry that must be used to transmit
 *
 */
IP_STATIC Ipnet_dst_cache *
ipnet_ip4_srr_process_local_tx(Ipnet_data *net,
                               Ipnet_flow_spec *flow_specp,
                               Ipnet_pkt_ip_opt *opt,
                               Ipnet_ip4_layer_info *info)
{
    Ipnet_dst_cache *dst = IP_NULL;
    Ip_u8           *optdata = (Ip_u8 *)opt;
    Ip_u32           ndst    = IP_GET_32ON8(optdata + optdata[2] - 1);
    Ipnet_flow_spec flow_spec = *flow_specp;

    if (optdata[2] != 4)
        return IP_NULL;

    for (;;)
    {
        ndst    = IP_GET_32ON8(optdata + 3);
        flow_spec.to.in.s_addr = ndst;

        /* Time to resolve the next hop */
        dst = ipnet_dst_cache_get(net, &flow_spec);
        if (IP_UNLIKELY(dst == IP_NULL))
        {
            int ret;
            ret = ipnet_dst_cache_new(net,
                                      &flow_spec,
                                      ipnet_ip4_dst_cache_local_tx_ctor,
                                      &dst);

            /* Failed to route? */
            if (ret < 0)
                return IP_NULL;
        }

        if (opt->len > 7)
        {
            /* Truncate */
            ipcom_memmove(optdata + 3, optdata + 7, (Ip_size_t) (opt->len - 7));
            /* Go NOP on the excess */
            IP_SET_32ON8(optdata + opt->len - 4, 0);
            /* Reduce opt size */
            opt->len = (Ip_u8) (opt->len - 4);
        }
        else
        {
            break;
        }

        if (dst->to_type == IPNET_ADDR_TYPE_NOT_LOCAL)
            break;
    }

    /* Just incase we've been subjected to the blackhole destination */
    if (IP_NULL != dst && 0 == info->ttl)
        info->ttl = (Ip_u8) dst->neigh->netif->conf.inet.base_hop_limit;

    return dst;
}

/*
 *===========================================================================
 *                    ipnet_ip4_add_opts
 *===========================================================================
 * Description: Adds any IPv4 options that should be included in the packet.
 * Parameters:  dst - destination cache entry for the flow this packet
 *                    follows.
 *              info - IPv4 layer information for IPv4
 *              pkt - The packet.
 * Returns:     The total length of all added options.
 *
 */
IP_STATIC int
ipnet_ip4_add_opts(Ipnet_dst_cache **pdst,
                   Ipnet_ip4_layer_info *info,
                   Ipcom_pkt *pkt)
{
    int               optlen;
    Ipnet_dst_cache  *dst = *pdst;
    Ipnet_data       *net = dst->net;
    Ipnet_pkt_ip_opt *opt = IP_NULL;

    if (info->opts == IP_NULL)
    {
        if (IP_BIT_ISFALSE(info->flags, IPNET_IP4_OPF_ROUTER_ALERT))
            return 0;
        else
        {
            /*
             * Add RFC2113 router alert option.
             */
            static const struct Ipnet_ip4_sock_opts router_alert = {
                4, /* Length of all options */
                {
                    IP_IPOPT_RA,
                    4, /* Option length */
                    0, /* Every router should examine pkt, hi 8 bits */
                    0  /* Every router should examine pkt, lo 8 bits */
                } /* Option buffer */
            };
            info->opts = (struct Ipnet_ip4_sock_opts *) &router_alert;
        }
    }

    ip_assert((info->opts->len & 0x3) == 0);

    if (pkt->start < info->opts->len)
        return IPNET_ERRNO(ENOSPC);

    if (pkt->offset == 0)
    {
        char                       *optdata;
        void                       *ipopts;
        int                         ret;

        /*
         * First fragment or non-fragmented IP-datagram. Add all
         * options.
         */
        optlen = info->opts->len;
        ipopts = ipcom_pkt_push_front(pkt, optlen);
        ipcom_memcpy(ipopts, info->opts->opts, (Ip_size_t)optlen);

        while (IP_NULL != (opt = ipnet_ip4_get_ip_opt_next(opt, ipopts, optlen)))
        {
            switch (opt->flag_class_num)
            {
            case IP_IPOPT_TIMESTAMP:
                ret = ipnet_ip4_process_ts_opt((Ipnet_pkt_ip_opt_timestamp *)opt,
                                               &dst->flow_spec.to.in.s_addr,
                                               pkt,
                                               IP_FALSE);
                if (ret < 0)
                    return ret;
                break;

                /* DO THE RECORD ROUTES */
            case IP_IPOPT_RR:
            case IP_IPOPT_LSRR:
            case IP_IPOPT_SSRR:
                optdata = (char *)opt;
                if (opt->len < 3 || (opt->len - 3) & 3)
                    return -IP_ERRNO_EINVAL;

                if (opt->flag_class_num == IP_IPOPT_RR)
                {
                    /* Record my own address */
                    if (optdata[2] + 3 <= opt->len)
                    {
                        IP_SET_32ON8(&optdata[3+optdata[2]-4], dst->laddr.in.s_addr);
                        optdata[2] = (char)(optdata[2] + 4);
                    }
                    break;
                }

                /* NOT 4 if forwarding scenario */
                if (optdata[2] != 4)
                    break;

                dst = ipnet_ip4_srr_process_local_tx(net, &dst->flow_spec, opt, info);
                if (IP_NULL == dst)
                    return -IP_ERRNO_EHOSTUNREACH;

                /* New destination cache do be used */
                *pdst = dst;
                break;
            }
        }
    }
    else
    {
        /*
         * Fragment, add only options that has the "copied" flag
         * set.
         */
        optlen = 0;
        while (IP_NULL != (opt = ipnet_ip4_get_ip_opt_next(opt, info->opts->opts, info->opts->len)))
        {
            /*
             * Add IP-options that has the "copied" flag set.
             */
            if (IP_IPOPT_COPIED(opt->flag_class_num))
            {
                optlen += opt->len;
                ipcom_memcpy(ipcom_pkt_push_front(pkt, opt->len),
                             opt,
                             opt->len);
            }
        }

        /*
         * Pad up to the next multiple of 4 bytes
         */
        while (optlen & 0x3)
        {
            *(Ip_u8 *) ipcom_pkt_push_front(pkt, 1) = IP_IPOPT_NOOP;
            optlen++;
        }
    }

    return optlen;
}


/*
 *===========================================================================
 *                    ipnet_ip4_add_hdr
 *===========================================================================
 * Description: Adds an IPv4 header, including options (if any).
 * Parameters:  dst - destination cache for the flow used by the
 *                    packet
 *              info - per-packet IP information.
 *              pkt - The packet.
 *              opt_len - Length of IPv4 options.
 *              ipv4_id - The value of the ID field for this IP datagram.
 * Returns:     0 failure else header length.
 *
 */
IP_STATIC int
ipnet_ip4_add_hdr(Ipnet_dst_cache *dst,
                  Ipnet_ip4_layer_info *info,
                  Ipcom_pkt *pkt,
                  int opt_len,
                  Ip_u16 ipv4_id,
                  Ip_bool isfrag)
{
    Ipnet_pkt_ip *iphdr;
    int           ipv4_hdr_len;
    int           pkt_len;

    /*
     * Layer 4 protocols must make sure that there is enough
     * header space for one L3 + one L2 header. Pseudo interface, like
     * IP tunnels, must make the same guarantees as L4 protocols.
     * Available header space can be increased by calling
     * ipnet_increase_hdr_space().
     */
    ip_assert(pkt->start >= (IPNET_IP_HDR_SIZE
                             + dst->neigh->netif->ipcom.link_hdr_size));


    /*
     * IP options has already been added so this function will always
     * add exactly 20 bytes.
     */
    iphdr = ipcom_pkt_push_front(pkt, IPNET_IP_HDR_SIZE);

    pkt_len = ipcom_pkt_get_length(pkt);
    if (IP_UNLIKELY(pkt_len > 0xffff))
        /*
         * Packet too big, cannot fit the packet length into the
         * 16-bit length field of the IPv4 header.
         */
        return -IP_ERRNO_EMSGSIZE;

    pkt->ipstart = pkt->start;
    ipv4_hdr_len = IPNET_IP_HDR_SIZE + opt_len;

    /*
     * Fill in IP header fields
     */
    iphdr->v_hl = (Ip_u8)(0x40 | (ipv4_hdr_len >> 2));
    iphdr->len  = (Ip_u16) ip_htons(pkt_len);
    /* head id should be net order
     * convert to net order, but frag pkt need not convert(original pkt already is) */
    if(isfrag)
        iphdr->id   = ipv4_id;
    else
        iphdr->id   = (Ip_u16) ip_htons(ipv4_id);
    iphdr->ttl  = info->ttl;
    iphdr->p    = info->proto;

    if (IP_BIT_ISFALSE(pkt->flags, IPCOM_PKT_FLAG_HAS_IP_HDR))
    {
        iphdr->tos  = dst->flow_spec.ds;
        IPNET_IP4_SET_IPADDR(iphdr->src, dst->laddr.in.s_addr);
        IPNET_IP4_SET_IPADDR(iphdr->dst, dst->flow_spec.to.in.s_addr);
    }
    else if (IPNET_IP4_GET_IPADDR(iphdr->src) == IP_INADDR_ANY)
        IPNET_IP4_SET_IPADDR(iphdr->src, dst->laddr.in.s_addr);
    
    iphdr->off  = (Ip_u16) ip_htons(pkt->offset >> 3);
    if (IP_BIT_ISSET(pkt->flags, IPCOM_PKT_FLAG_MORE_FRAG))
        IP_BIT_SET(iphdr->off, IPNET_OFF_MF);
    if (IP_BIT_ISSET(info->flags, IPNET_IP4_OPF_DONT_FRAG)
        && (dst->peer_info == IP_NULL || !IPNET_PEER_INFO_ZERO_PMTU(dst->peer_info)))
        IP_BIT_SET(iphdr->off, IPNET_OFF_DF);

    /*
     * Calculat the IP header checksum
     */
    iphdr->sum = 0;
    iphdr->sum = ipcom_in_checksum(iphdr, (Ip_size_t)ipv4_hdr_len);

    IP_BIT_SET(pkt->flags, IPCOM_PKT_FLAG_HAS_IP_HDR);
    return ipv4_hdr_len;
}


/*
 *===========================================================================
 *                    ipnet_ip4_remove_header
 *===========================================================================
 * Description: Removes IPv4 header + any IP options.
 * Parameters:  pkt - The packet which has a IPv4 header.
 *              ipv4_id - Will contain the IP ID field from the removed packet.
 * Returns:     The length of the remove IPv4 header.
 *
 */
IP_STATIC int
ipnet_ip4_remove_header(Ipcom_pkt *pkt, Ip_u16 *ipv4_id)
{
    int           ipv4_opt_len;
    Ipnet_pkt_ip *ip_hdr = ipcom_pkt_get_iphdr(pkt);

    ip_assert(IP_BIT_ISSET(pkt->flags, IPCOM_PKT_FLAG_HAS_IP_HDR));

    /*
     * The IP header must be recreated. Remove it for now and extract
     * the fragmentation ID.
     */
    IP_BIT_CLR(pkt->flags, IPCOM_PKT_FLAG_HAS_IP_HDR);
    ipv4_opt_len = IPNET_IP4_GET_OPTS_OCTET_LEN(ip_hdr);
    *ipv4_id = ip_hdr->id;
    pkt->start += ipv4_opt_len + IPNET_IP_HDR_SIZE;
    return ipv4_opt_len;
}


/*
 *===========================================================================
 *                    ipnet_ip4_get_offset
 *===========================================================================
 * Description: Returns the offset for this segment into the IP packet.
 * Parameters:  frag - A IPv4 fragment.
 * Returns:     The offset.
 *
 */
IP_STATIC Ip_u16
ipnet_ip4_get_offset(Ipcom_pkt *frag)
{
    Ipnet_pkt_ip *ip4_hdr;

    ip4_hdr = ipcom_pkt_get_iphdr(frag);
    return (Ip_u16) (ip_ntohs(ip4_hdr->off & IPNET_OFF_MASK) << 3);
}


/*
 *===========================================================================
 *                    ipnet_ip4_more_fragments
 *===========================================================================
 * Description: Returns if this is the last fragment or not.
 * Parameters:  frag - A IPv4 fragment.
 * Returns:     IP_TRUE or IP_FALSE.
 *
 */
IP_STATIC Ip_bool
ipnet_ip4_more_fragments(Ipcom_pkt *frag)
{
    Ipnet_pkt_ip *iphdr;

    iphdr = ipcom_pkt_get_iphdr(frag);
    return IP_BIT_ISSET(iphdr->off, IPNET_OFF_MF);
}


/*
 *===========================================================================
 *                    ipnet_ip4_update_ip_header
 *===========================================================================
 * Description: Sets the IPv4 length, offset and chk for the reassembled
 *              packet.
 * Parameters:  pkt - The reassembled IPv4 packet.
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_update_ip_header(Ipcom_pkt *pkt)
{
    Ipnet_pkt_ip *ip_hdr;

    ip_hdr = ipcom_pkt_get_iphdr(pkt);

    /*
     * This packet does not contain a fragmentation header
     */
    ip_hdr->len = (Ip_u16) ip_htons(ipcom_pkt_get_length(pkt));
    ip_hdr->off = 0;

    /*
     * No need to calculate the checksum since it was done on the
     * individual fragments
     */
    ip_hdr->sum = 0;
}



/*
 *===========================================================================
 *                       ipnet_ip4_dst_unreachable
 *===========================================================================
 * Description: The packet is sent to a node that is unreachable.
 * Parameters:  pkt - a packet
 *              err - error code that describes why the destination is
 *                    unreachable.
 * Returns:
 *
 */
IP_GLOBAL void
ipnet_ip4_dst_unreachable(Ipcom_pkt *pkt, int err)
{
    Ipnet_icmp_param icmp_param;
    Ipnet_pkt_ip    *ip = ipcom_pkt_get_iphdr(pkt);

    if (pkt->ipstart < pkt->start
        || pkt->ipstart + IPNET_IP_HDR_SIZE > pkt->end
        || (ip->v_hl & 0xF0) != 0x40)
        /* Cannot be a valid IPv4 packet */
        return;

    ipnet_icmp4_param_init(&icmp_param, pkt);

    icmp_param.type = IPNET_ICMP4_TYPE_DST_UNREACHABLE;
    switch (err)
    {
    case IP_ERRNO_EACCES:
        icmp_param.code = IPNET_ICMP4_CODE_DST_PROHIBITED_NET;
        break;
    case IP_ERRNO_EPERM:
        icmp_param.code = IPNET_ICMP4_CODE_DST_PROHIBITED_HOST;
        break;
    case IP_ERRNO_EHOSTUNREACH:
        icmp_param.code = IPNET_ICMP4_CODE_DST_UNREACH_HOST;
        break;
    default:
        icmp_param.code = IPNET_ICMP4_CODE_DST_UNREACH_NET;
        break;
    }

    (void) ipnet_icmp4_send(&icmp_param, IP_FALSE);
}

/*
 *===========================================================================
 *                       ipnet_ip4_dst_unreachable_filter
 *===========================================================================
 * Description: The packet is sent to a node that is unreachable because
 *              filter drop this packet.
 * Parameters:  pkt - a packet
 * Returns:
 *
 */
IP_GLOBAL void
ipnet_ip4_dst_unreachable_filter(Ipcom_pkt *pkt)
{
    Ipnet_icmp_param icmp_param;
    Ipnet_pkt_ip    *ip = ipcom_pkt_get_iphdr(pkt);

    if (pkt->ipstart < pkt->start
        || pkt->ipstart + IPNET_IP_HDR_SIZE > pkt->end
        || (ip->v_hl & 0xF0) != 0x40)
        /* Cannot be a valid IPv4 packet */
        return;

    ipnet_icmp4_param_init(&icmp_param, pkt);

    icmp_param.type = IPNET_ICMP4_TYPE_DST_UNREACHABLE;
    icmp_param.code = IPNET_ICMP4_CODE_DST_PROHIBITED_ADM;
    (void) ipnet_icmp4_send(&icmp_param, IP_FALSE);
}


/*
 *===========================================================================
 *                    ipnet_ip4_fragment_timeout
 *===========================================================================
 * Description: Time-out handler for fragment reassembly.
 * Parameters:  frag_head - list of fragments that has been received
 *                          for a specific IP-datagram
 * Returns:
 *
 */
IP_GLOBAL void
ipnet_ip4_fragment_timeout(Ipcom_pkt *frag_head)
{
    Ipnet_icmp_param  p;
    Ipnet_data       *net = ipnet_ptr();
#ifdef IPCOM_USE_MIB2
    Ipnet_netif *netif = ipnet_if_indextonetif(frag_head->vr_index, frag_head->ifindex);
    if (netif != IP_NULL)
    {
        IPCOM_MIB2(net, ipReasmFails++);
        IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsReasmFails, 1);
        IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsReasmFails, 1, netif, ipnet_instance_idx(net));
    }
#endif /* IPCOM_USE_MIB2 */

    /*
     * Possibly send a time exceeded message, will only be sent if the
     * first fragment has been received
     */
    ipnet_icmp4_param_init(&p, frag_head);
    p.type = IPNET_ICMP4_TYPE_TIME_EXCEEDED;
    p.code = IPNET_ICMP4_CODE_TIM_REASSEMBLY;
    (void) ipnet_icmp4_send(&p, IP_FALSE);

    ipcom_pkt_free(frag_head);
}


/*
 *===========================================================================
 *               ipnet_ip4_unsupported_transport_layer_rx
 *===========================================================================
 * Description: Handler for all IP-protocol that is not implemented by
 *              this network stack.
 * Parameters:  dst - a destination cache entry
 *              ingress_pkt - IP datagram that uses a protocol not
 *              implemented by this stack
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_unsupported_transport_layer_rx(Ipnet_dst_cache *dst,
                                         Ipcom_pkt *pkt)
{
#if defined(IPCOM_FORWARDER_NAE)
    ipnet_nae_unsupported_transport_layer_rx(dst, pkt);
#else /* !defined(IPCOM_FORWARDER_NAE) */
    int         ret;
#ifdef IPCOM_USE_MIB2
    Ipnet_data *net = ipnet_pkt_get_stack_instance(pkt);
#endif

    ret = ipnet_ip4_deliver_to_raw_sock(dst, pkt, IP_FALSE);

    if (ret < 0)
        dst->ingress_netif->stats[pkt->stack_idx].noproto++;

    if (ret == -IP_ERRNO_EPROTONOSUPPORT
        && (IP_IN_CLASSA(dst->flow_spec.to.in.s_addr)
            || IP_IN_CLASSB(dst->flow_spec.to.in.s_addr)
            || IP_IN_CLASSC(dst->flow_spec.to.in.s_addr)))
    {
        Ipnet_icmp_param icmp_param;

        /*
         * No AF_RAW socket was listening to this protocol protocol
         * handler for this protocol and packet was sent to one of the
         * locally assigned addresses.
         */
        IPCOM_MIB2(net, ipInUnknownProtos++);
        IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsInUnknownProtos, 1);
        IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsInUnknownProtos, 1, dst->ingress_netif, pkt->stack_idx);

        ipnet_icmp4_param_init(&icmp_param, pkt);
        icmp_param.type     = IPNET_ICMP4_TYPE_DST_UNREACHABLE;
        icmp_param.code     = IPNET_ICMP4_CODE_DST_UNREACH_PROTO;
        icmp_param.recv_pkt = pkt;
        (void) ipnet_icmp4_send(&icmp_param, IP_FALSE);
#ifndef IP_PORT_LKM
        /*
         * The LKM port will always free the
         * icmp_param.recv_pkt. All other ports must manually free
         * the packet.
         */
        ipcom_pkt_free(pkt);
#endif
    }
    else
    {
        /*
         * No ICMP message should be sent
         */
        if (ret == 0)
        {
            /*
             * Packet was queued on at least one AF_RAW socket
             */
            IPCOM_MIB2(net, ipInDelivers++);
            IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCInDelivers, 1);
            IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCInDelivers, 1, dst->ingress_netif, pkt->stack_idx);
        }
        ipcom_pkt_free(pkt);
    }
#endif /* !defined(IPCOM_FORWARDER_NAE) */
}



/*
 *===========================================================================
 *                           ipnet_ip4_frag_tx
 *===========================================================================
 * Description: Transmission handler for packet, both forwarded and
 *              locally generated, that must be fragmented before it
 *              can be transmitted.
 * Parameters:  dst - destination cache for the flow to use
 *              pkt - packet that must be fragmented.
 *              tx_func - function that will send the finished IP
 *                        fragments.
 * Returns:     0 = success
 *             <0 = error code
 *
 */
IP_STATIC int
ipnet_ip4_frag_tx(Ipnet_dst_cache *dst,
                  Ipcom_pkt *pkt,
                  Ipnet_dst_cache_tx_func tx_func)
{
    Ipcom_pkt            *next_fragment;
    Ipnet_icmp_param      icmp_param;
    Ipnet_ip4_layer_info *ip4_info;
    int                   ipv4_opt_len;
    Ip_u32                path_mtu = dst->path_mtu;
    Ipnet_netif          *netif = dst->neigh->netif;
    Ip_u16                ip4_id;
    int                   ret;
    Ipnet_data *net = ipnet_pkt_get_stack_instance(pkt);

    ip4_info = IPNET_IP4_GET_LAYER_INFO(pkt);

    if (IP_BIT_ISSET(ip4_info->flags, IPNET_IP4_OPF_NO_LOCAL_FRAG))
    {
        /*
         * Local fragmentation is not allowed.
         */
        ipcom_pkt_free(pkt);
        return IPNET_ERRNO(EMSGSIZE);
    }

    IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsOutFragReqds, 1);
    IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsOutFragReqds, 1, netif, pkt->stack_idx);

    if (IP_BIT_ISSET(ip4_info->flags, IPNET_IP4_OPF_DONT_FRAG)
        && (IP_BIT_ISSET(pkt->flags, IPCOM_PKT_FLAG_FORWARDED)
            || pkt->ipsec_hlen != 0))
    {
        /*
         * This packet is not allowed to be fragmented, send ICMP need
         * fragmentation to the sender of this packet.
         */
        if (pkt->ipsec_hlen != 0)
        {
            Ipcom_pkt *pkt_orig;

            /* Reduce MTU for IPSEC */
            path_mtu -= (int)pkt->ipsec_hlen;

            /* Recycle the original packet */
            if(pkt->next_original)
            {
                pkt_orig = pkt->next_original;
                ip_assert(pkt_orig != IP_NULL);
                pkt->next_original = IP_NULL;
                ipcom_pkt_free(pkt);
                pkt = pkt_orig;
                pkt->start = pkt->ipstart;
            }
            else
            {
                /* IPsec has already re-used the original packet,
                 * the original is lost. Can't send ICMP */
                ipcom_pkt_free(pkt);
                return IPNET_ERRNO(EMSGSIZE);
            }

            /* Set packet interface index to original ingress interface */
            pkt->ifindex = *(unsigned *)ipcom_pkt_get_info_safe(pkt, IPNET_PKT_INFO_INGRESS_IFINDEX);
        }

        ipnet_icmp4_param_init(&icmp_param, pkt);
        icmp_param.type = IPNET_ICMP4_TYPE_DST_UNREACHABLE;
        icmp_param.code = IPNET_ICMP4_CODE_DST_NEEDFRAG;
        icmp_param.data.max_path_mtu = path_mtu;
        (void) ipnet_icmp4_send(&icmp_param, IP_FALSE);
        IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_INFO,
                          1, 14, IPCOM_WV_NETDEVENT_INFO, IPCOM_WV_NETD_SEND,
                          ipnet_ip4_frag_tx, IPCOM_WV_NETD_INFO_DROPPED,
                          IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
        IPNET_STATS(net, ip4_input_need_frag++);
        IPCOM_MIB2(net, ipFragFails++);
        IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsOutFragFails, 1);
        IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsOutFragFails, 1, netif, pkt->stack_idx);
        ipcom_pkt_free(pkt);
        return IPNET_ERRNO(EMSGSIZE);
    }

    /*
     * L4 checksum has already been calculated before this point and
     * it should not be recalculated.
     */
    ip4_info->chksum_ptr = IP_NULL;

    /*
     * Generate a new fragmentation ID unless this packet already has
     * an IP header, in which case that fragmentation ID is extracted
     * and used.
     */
    if (IP_BIT_ISSET(pkt->flags, IPCOM_PKT_FLAG_HAS_IP_HDR))
        ipv4_opt_len = ipnet_ip4_remove_header(pkt, &ip4_id);
    else
    {
        ipv4_opt_len = ipnet_ip4_add_opts(&dst, ip4_info, pkt);
        ipnet_ip4_get_ip_id(dst, ip4_info, &ip4_id);
    }

    pkt = ipnet_fragment_packet(pkt,
                                IPNET_IP_HDR_SIZE + ipv4_opt_len,
                                0,
                                (int)path_mtu,
                                ipnet_ip4_more_fragments);
    if (pkt == IP_NULL)
    {
        /* The original packet is free'd by ipnet_fragment_packet() */
        IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_CRITICAL,
                          1, 15, IPCOM_WV_NETDEVENT_CRITICAL, IPCOM_WV_NETD_SEND,
                          ipnet_ip4_frag_tx, IPCOM_WV_NETD_NOBUFS,
                          IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
        IPNET_STATS(net, ip4_output_enobufs++);
        IPCOM_MIB2(net, ipFragFails++);
        IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsOutFragFails, 1);
        IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsOutFragFails, 1, netif, ipnet_instance_idx(net));
        IPCOM_MIB2(net, ipOutDiscards++);
        IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsOutDiscards, 1);
        IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsOutDiscards, 1, netif, ipnet_instance_idx(net));
        return IPNET_ERRNO(ENOBUFS);
    }

    /*
     * Fragments successfully generated.
     */
    IPCOM_MIB2(net, ipFragOKs++);
    IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsOutFragOKs, 1);
    IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsOutFragOKs, 1, netif, ipnet_instance_idx(net));

    do
    {
        next_fragment = pkt->next_fragment;
        pkt->next_fragment = IP_NULL;

        /*
         * Add IPv4 header and IP options (if any)
         */
        ipv4_opt_len = ipnet_ip4_add_opts(&dst, ip4_info, pkt);
        if (IP_LIKELY(ipv4_opt_len >= 0))
            ret = ipnet_ip4_add_hdr(dst,
                                    ip4_info,
                                    pkt,
                                    ipv4_opt_len,
                                    ip4_id,
                                    IP_TRUE);
        else
            ret = ipv4_opt_len;

        if (IP_UNLIKELY(ret < 0))
        {
            pkt->next_fragment = next_fragment;
            break;
        }

        pkt->ifindex = netif->ipcom.ifindex;
        
        IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCOutTransmits, 1);
        IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCOutTransmits, 1, netif, pkt->stack_idx);
        
        ret = tx_func(dst, pkt);
    } while (IP_NULL != (pkt = next_fragment)
             && ret >= 0);

    if (IP_UNLIKELY(pkt != IP_NULL))
        ipcom_pkt_free(pkt);

    return ret;
}



/*
 *===========================================================================
 *                       ipnet_ip4_neigh_tx_adapter
 *===========================================================================
 * Description: Adapts the neighbor output function to a destination
 *              cache transmit function.
 * Parameters:  dst - a destination cache entry
 *              pkt - packet to send, must contain a IP header.
 * Returns:     0 = success
 *             <0 = error code
 *
 */
IP_STATIC int
ipnet_ip4_neigh_tx_adapter(Ipnet_dst_cache *dst, Ipcom_pkt *pkt)
{
    Ipnet_neigh          *neigh;
    Ipnet_ip4_layer_info *ip4_info = IPNET_IP4_GET_LAYER_INFO(pkt);

    if (ip4_info->nexthop)
        neigh = ip4_info->nexthop;
    else
        neigh = dst->neigh;

    return ipnet_neigh_tx(neigh, dst, pkt);
}



/*
 *===========================================================================
 *                       ipnet_ip4_finish_l4_chksum
 *===========================================================================
 * Description: Finishes the layer 4 checksum by appending the pseudo
 *              header checksum.
 * Parameters:  dst - destination cache followed by the packet
 *              ip4_info - IPv4 protocol information
 *              pkt - a packet, pkt->start must be the offset to the
 *                    transport layer header and pkt->end the offset
 *                    to the end of the transport payload.
 * Returns:
 *
 */
IP_INLINE void
ipnet_ip4_finish_l4_chksum(Ipnet_dst_cache *dst,
                           Ipnet_ip4_layer_info *ip4_info,
                           Ipcom_pkt *pkt)
{
    Ip_u32 sum;
    Ip_u16 pkt_len = (Ip_u16)ipcom_pkt_get_length(pkt);

    /*
     * Should never need to calculate transport header checksum on
     * forwarded packets
     */
    ip_assert(IP_BIT_ISFALSE(pkt->flags, IPCOM_PKT_FLAG_HAS_IP_HDR));

    sum = ipnet_ip4_pseudo_header_checksum_update(&dst->laddr.in,
                                                        &dst->flow_spec.to.in,
                                                        ip4_info->proto,
                                                        pkt_len);
    pkt->chk +=sum;
    *ip4_info->chksum_ptr = ipcom_in_checksum_finish(pkt->chk);

    /*
     * Fix-up the UDP checksum if it was calculated to 0
     */
    if (*ip4_info->chksum_ptr == 0
        && (ip4_info->proto == IP_IPPROTO_UDP
            || ip4_info->proto == IP_IPPROTO_UDPLITE))
        *ip4_info->chksum_ptr = 0xFFFF;
}


/*
 *===========================================================================
 *                         ipnet_ip4_local_tx
 *===========================================================================
 * Description: Transmits a packet created at the local node. This
 *              handler deals only with unicast transmits.
 * Parameters:  dst - destination cache entry to use
 *              pkt - packet to transmit
 * Returns:     0 = success
 *             <0 = error code
 *
 */
IP_STATIC int
ipnet_ip4_local_tx(Ipnet_dst_cache *dst, Ipcom_pkt *pkt)
{
    Ipnet_ip4_layer_info *ip4_info;
    int                   ipv4_opt_len;
    int                   ret;
    Ip_u16                ip4_id;
    int                   pkt_len;
    Ipnet_netif          *netif;

#if defined(IPCOM_USE_MIB2) || defined(IPNET_STATISTICS) || defined(IPNET_DEBUG)
    Ipnet_data         *net = ipnet_pkt_get_stack_instance(pkt);
#endif

    IPNET_DEBUG_LINE(ip_assert(IPCOM_GET_PKT_ID(pkt) != IPCOM_PKT_ID_FREEQ));
    IPNET_DEBUG_LINE(ip_assert(IPCOM_GET_PKT_ID(pkt) != IPCOM_PKT_ID_INQ));
    IPCOM_PKT_TRACE(pkt, IPCOM_PKT_ID_IP4_OUTPUT);
    IPNET_DEBUG_LINE(ipnet_pkt_check(pkt));

    ip4_info = IPNET_IP4_GET_LAYER_INFO(pkt);

    netif = dst->neigh->netif;
    if (IP_UNLIKELY(ip4_info->nexthop))
        netif = ip4_info->nexthop->netif;

    /*
     * Set pkt->ifindex to the egress network interface.
     */
    pkt->ifindex = netif->ipcom.ifindex;

    /*
     * Check if the transport layer checksum must be finished
     */
    if (ip4_info->chksum_ptr
        && IP_BIT_ISFALSE(pkt->flags, IPCOM_PKT_FLAG_HAS_IP_HDR))
    {
        ipnet_ip4_finish_l4_chksum(dst, ip4_info, pkt);
    }
    pkt->tlstart = pkt->start;

#ifdef IPIPSEC2
    if (IP_BIT_ISTRUE(pkt->flags, IPCOM_PKT_FLAG_IPSEC_OUT))
    {
        /*
         * IPSec already set the identifier and it may be part of the ICV.
         * Get it from the header instead.
         */
        Ipnet_pkt_ip *ip_hdr;

        ip_hdr = ipcom_pkt_get_data(pkt, -IPNET_IP_HDR_SIZE);
        ip4_id = ip_hdr->id;
    }
    else
#endif
    {
        /**/
        ipnet_ip4_get_ip_id(dst, ip4_info, &ip4_id);
    }

    /*
     * Add IPv4 header and options.
     */
    ipv4_opt_len = ipnet_ip4_add_opts(&dst, ip4_info, pkt);
    if (IP_LIKELY(ipv4_opt_len >= 0))
        ret = ipnet_ip4_add_hdr(dst,
                                ip4_info,
                                pkt,
                                ipv4_opt_len,
                                ip4_id,
                                IP_FALSE);
    else
        /*
         * Failed to add the IP options for some reason...
         */
        ret = ipv4_opt_len;

    if (IP_UNLIKELY(ret < 0))
        goto errout;

#if defined(IPNET_USE_DIFFSERV) && !defined(IPNET_DIFFSERV_CLASSIFIER_MODE_BA)
    dst = ipnet_diffserv_local_tx(dst,
                                  pkt,
                                  ipnet_ip4_dst_cache_local_tx_ctor);
#endif /* IPNET_USE_DIFFSERV && !IPNET_DIFFSERV_CLASSIFIER_MODE_BA */

    /*
     * Time to check Firewall, NAT and IPSEC
     */
#if defined(IPNET_USE_NAT) || defined(IPFIREWALL) || defined(IPIPSEC2)
    ret = ipnet_fw_nat_ipsec_tx(&dst, &pkt, IP_TRUE);
    if (ret < 0)
    {
        /* Drop packet */
        goto errout;
    }
    else if (ret > 0)
    {
        /* Packet absorbed */
        return 0;
    }
    else
    {
        Ipnet_pkt_ip *ip_hdr;

        /* OK */
        ip_hdr = ipcom_pkt_get_iphdr(pkt);
        ip4_info->proto = ip_hdr->p;
    }

    /*
     * Set pkt->ifindex to the egress network interface.
     * NAT/FW/IPSEC may change dst cache entry
     */
    if (ip4_info->nexthop == IP_NULL)
    {
        netif = dst->neigh->netif;
        pkt->ifindex = netif->ipcom.ifindex;
    }

#endif /* defined(IPNET_USE_NAT) || defined(IPFIREWALL) || defined(IPIPSEC2) */

    pkt_len = ipcom_pkt_get_length(pkt);
    IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCOutOctets, pkt_len);
    IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCOutOctets, pkt_len, netif, pkt->stack_idx);
    /*
     * Check if this packet must be fragmented
     */
    if (IP_UNLIKELY((unsigned) pkt_len > dst->path_mtu))
        return ipnet_ip4_frag_tx(dst, pkt, ipnet_ip4_neigh_tx_adapter);

#ifdef IPROHC
    if (iprohc.opened
        && (netif->ipcom.type != IP_IFT_TUNNEL))
    {
        /*
         * Do ROHC on a not (TUNNEL) interface
         */
        ret = iprohc_output_hook(&netif->ipcom, pkt);
        if (ret != IPCOM_SUCCESS)
        {
            /* ROHC failed */
            IPCOM_LOG1(WARNING, "Discarding IPv4 datagram on %s, ROHC failed.", netif->ipcom.name);
            ret = IPNET_ERRNO(EROHC);
            goto errout;
        }
    }
#endif /* IPROHC */

    IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCOutTransmits, 1);
    IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCOutTransmits, 1, netif, pkt->stack_idx);

    if (IP_UNLIKELY(ip4_info->nexthop))
        return ipnet_neigh_tx(ip4_info->nexthop, dst, pkt);

    return ipnet_neigh_tx(dst->neigh, dst, pkt);

 errout:
    ipcom_pkt_free(pkt);
    return ret;
}



/*
 *===========================================================================
 *                           ipnet_ip4_local_rx
 *===========================================================================
 * Description: Receives a packet targeted for this node. This handler
 *              can only handle packets sent to one of the local
 *              unicast addresses.
 * Parameters:  dst - destination cache entry
 *              pkt - packet received
 * Returns:     0 = success
 *             <0 = error code
 *
 */
IP_STATIC int
ipnet_ip4_local_rx(Ipnet_dst_cache *dst, Ipcom_pkt *pkt)
{
    const Ipnet_pkt_ip *ip_hdr;
    int                 ip_hdr_len;
#if defined(IPNET_USE_NAT) || defined(IPFIREWALL) || defined(IPIPSEC2)
    int                 ret;
#endif
#if defined(IPCOM_USE_MIB2) || defined(IPNET_STATISTICS) || defined(IPNET_DEBUG)
    Ipnet_data         *net = ipnet_pkt_get_stack_instance(pkt);
#endif
#ifdef IPCOM_USE_MIB2
    int                 stack_idx = pkt->stack_idx;
#endif

    ip_hdr = ipcom_pkt_get_iphdr(pkt);
    ip_hdr_len = IPNET_IP4_GET_HDR_OCTET_LEN(ip_hdr);

    if (IP_UNLIKELY(IPNET_ISFRAG(ip_hdr->off)))
    {
        Ipcom_pkt *ip_fragment_list;

        /*
         * The start point must point to the IP payload when put into
         * the fragmentation list. The reassembled packet will have
         * its pkt->start set to the IP header.
         */
        ipcom_pkt_pop_front(pkt, ip_hdr_len);

        /*
         * RFC 791, page 23:
         * "If an internet datagram is fragmented, its data portion must be
         * broken on 8 octet boundaries."
         */
        if (IP_UNLIKELY(ipcom_pkt_get_length(pkt) % 8 != 0
                        && ipnet_ip4_more_fragments(pkt)))
        {
            /*
             * Not last fragment and not a multiple of 8, invalid fragment.
             */
            ipcom_pkt_free(pkt);
            return IPNET_ERRNO(EINVAL);
        }

        /*
         * This IP datagram is a fragment, check if all fragments has
         * been received.
         */
        IPCOM_MIB2(net, ipReasmReqds++);
        IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsReasmReqds, 1);
        IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsReasmReqds, 1, dst->ingress_netif, stack_idx);
        IPCOM_PKT_TRACE(pkt, IPCOM_PKT_ID_IP4_REASSEMBLY);

        IPNET_DEBUG_LINE(ipnet_frag_set_peer_info(pkt, dst->peer_info));
        pkt->offset = ipnet_ip4_get_offset(pkt);

        ip_fragment_list = ipnet_reassembly(dst->net,
                                            dst->peer_info,
                                            pkt,
                                            ipnet_ip4_is_part_of_same_pkt,
                                            ipnet_ip4_more_fragments);
        if (ip_fragment_list == IP_NULL)
            /*
             * More fragments needed
             */
            return 0;

        /*
         * All fragments has been received, reassemble them into one
         * large IP datagram.
         */
        pkt = ipnet_create_reassembled_packet(ip_fragment_list,
                                              ipnet_ip4_update_ip_header,
                                              IP_NULL);
        if (pkt == IP_NULL)
        {
            IPCOM_MIB2(net, ipInDiscards++);
            IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsInDiscards, 1);
            IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsInDiscards, 1, dst->ingress_netif, stack_idx);
            IPCOM_MIB2(net, ipReasmFails++);
            IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsReasmFails, 1);
            IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsReasmFails, 1, dst->ingress_netif, stack_idx);
            IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_CRITICAL,
                              1, 37, IPCOM_WV_NETDEVENT_CRITICAL, IPCOM_WV_NETD_RECV,
                              ipnet_ip4_local_rx, IPCOM_WV_NETD_NOBUFS,
                              IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
            IPNET_STATS(net, ip4_input_reasm_enobufs++);
            return IPNET_ERRNO(ENOBUFS);
        }

        IPCOM_MIB2(net, ipReasmOKs++);
        IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsReasmOKs, 1);
        IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsReasmOKs, 1, dst->ingress_netif, stack_idx);

        ip_hdr = ipcom_pkt_get_iphdr(pkt);
        ip_hdr_len = IPNET_IP4_GET_HDR_OCTET_LEN(ip_hdr);
        IP_BIT_SET(pkt->flags, IPCOM_PKT_FLAG_IPV4);
    }

    /*
     * Move the start pointer to the IP payload.
     */
    pkt->start  += ip_hdr_len;

#ifdef IPIPSEC2
    if ((ip_hdr->p != IP_IPPROTO_ESP && ip_hdr->p != IP_IPPROTO_AH)
        || pkt->ipsec_no_sa == 1)
    {
#endif
        /*
         * Time to check Firewall and NAT
         */
#if defined(IPNET_USE_NAT) || defined(IPFIREWALL) || defined(IPIPSEC2)
        ret = ipnet_fw_nat_rx(&dst, &pkt, IP_TRUE);
        if (ret < 0)
        {
            /* Drop packet */
            ipcom_pkt_free(pkt);
            return ret;
        }
        else if (ret > 0)
        {
            /* Packet transformed */
            return ipnet_dst_cache_rx(dst, pkt);
        }
#endif /* defined(IPNET_USE_NAT) || defined(IPFIREWALL) || defined(IPIPSEC2) */

#ifdef IPIPSEC2
    }
#endif

    /*
     * Deliver to transport layer handler for the protocol stated in
     * the IP header.
     */
    ipnet_ip4_transport_layer_rx[ip_hdr->p](dst, pkt);
    return 0;
}



/*
 *===========================================================================
 *                           ipnet_ip4_bcast_rx
 *===========================================================================
 * Description: Broadcast reception handler.
 * Parameters:  dst - destination cache entry.
 *              pkt - broadcst IP datagram
 * Returns:     0 = success
 *             <0 = error code
 *
 */
IP_STATIC int
ipnet_ip4_bcast_rx(Ipnet_dst_cache *dst, Ipcom_pkt *pkt)
{
#ifdef IPCOM_USE_MIB2
    Ipnet_data *net = ipnet_pkt_get_stack_instance(pkt);
#endif

    IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCInBcastPkts, 1);
    IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCInBcastPkts, 1, dst->neigh->netif, pkt->stack_idx);
    return ipnet_ip4_local_rx(dst, pkt);
}


/*
 *===========================================================================
 *                           ipnet_ip4_mcast_rx
 *===========================================================================
 * Description: Receives a multicast packet. dst->to_type will be set
 *              to IPNET_ADDR_TYPE_MULTICAST if the local node listens
 *              to this address.
 * Parameters:  dst - destination cache entry
 *              pkt - packet received
 * Returns:     0 = success
 *             <0 = error code
 *
 */
IP_STATIC int
ipnet_ip4_mcast_rx(Ipnet_dst_cache *dst, Ipcom_pkt *pkt)
{
    Ipnet_netif *netif = dst->ingress_netif;
#if defined(IPCOM_USE_MIB2) || defined(IPNET_STATISTICS) || defined(IPNET_DEBUG)
    Ipnet_data  *net = ipnet_pkt_get_stack_instance(pkt);
#endif

    netif->stats[pkt->stack_idx].imcasts++;
    IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCInMcastPkts, 1);
    IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCInMcastPkts, 1, netif, pkt->stack_idx);
    /* coverity[check_return] */
    IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCInMcastOctets, ipcom_pkt_get_length(pkt));
    /* coverity[check_return] */
    IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCInMcastOctets, ipcom_pkt_get_length(pkt), netif, pkt->stack_idx);

#ifdef IPNET_USE_MCAST_ROUTING
    do {
        const Ipnet_pkt_ip *ip_hdr = ipcom_pkt_get_iphdr(pkt);

        if (ip_hdr->p != IP_IPPROTO_IGMP
            && ((ip_ntohl(dst->flow_spec.to.in.s_addr) & 0xffffff00) != 0xe0000000))
        {
            /*
             * Input packets for multicast routing unless they are
             * IGMP packets or in the 224.0.0.0/24 network
             */
            if (IPNET_ISFRAG(ip_hdr->off))
                pkt->offset = ipnet_ip4_get_offset(pkt);
            ipnet_ip4_mcast_input(netif, pkt);
        }
    }
    while (0);
#endif /* IPNET_USE_MCAST_ROUTING */

    if (dst->to_type == IPNET_ADDR_TYPE_NOT_LOCAL
        && IP_BIT_ISFALSE(netif->ipcom.flags, IP_IFF_ALLMULTI))
    {
        IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_WARNING,
                          1, 35, IPCOM_WV_NETDEVENT_WARNING, IPCOM_WV_NETD_RECV,
                          ipnet_ip4_mcast_rx, IPCOM_WV_NETD_BADADDR,
                          IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
        IPNET_STATS(net, ip4_input_not_to_me++);
        IPCOM_MIB2(net, ipInAddrErrors++);
        IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsInAddrErrors, 1);
        IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsInAddrErrors, 1, netif, pkt->stack_idx);
        ipcom_pkt_free(pkt);
        return 0;
    }

    /*
     * This packet should be delivered locally, either because it was
     * sent to a group this node is listening to or the node has been
     * configured to receive all multicast IP-datagrams.
     */
    return ipnet_ip4_local_rx(dst, pkt);
}


/*
 *===========================================================================
 *                         ipnet_ip4_loop_pkt_tx
 *===========================================================================
 * Description: Helper function to send a copy of a packet through the
 *              loopback interface.
 * Parameters:  dst - destination cache entry
 *              pkt - packet to send
 *              dst_cache_local_tx_ctor - TX destination cache ctor
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_loop_pkt_tx(Ipnet_dst_cache *dst,
                      Ipcom_pkt *pkt,
                      Ipnet_dst_cache_domain_ctor dst_cache_local_tx_ctor)
{
    /* Init layer info */
    Ipnet_ip4_layer_info *ip4_info_orig = IPNET_IP4_GET_LAYER_INFO(pkt);
    Ipnet_ip4_layer_info ip4_info       = *ip4_info_orig;

    /*
     * Have to do it this way -- fragmentation and other routines can
     * change the layer info -- resulting in corrupt TX frames
     */
    IPNET_IP4_SET_LAYER_INFO(pkt, &ip4_info);
    ipnet_loop_pkt_tx(dst, pkt, dst_cache_local_tx_ctor);
    IPNET_IP4_SET_LAYER_INFO(pkt, ip4_info_orig);
}


/*
 *===========================================================================
 *                           ipnet_ip4_mcast_tx
 *===========================================================================
 * Description: Transmits a multicast packet.
 * Parameters:  dst - destination cache entry
 *              pkt - packet received
 * Returns:     0 = success
 *             <0 = error code
 *
 */
IP_STATIC int
ipnet_ip4_mcast_tx(Ipnet_dst_cache *dst, Ipcom_pkt *pkt)
{
#ifdef IPCOM_USE_MIB2
    Ipnet_data *net = ipnet_pkt_get_stack_instance(pkt);
#endif
    Ipnet_netif *netif = dst->neigh->netif;

    ipnet_ip4_loop_pkt_tx(dst, pkt, ipnet_ip4_dst_cache_local_tx_ctor);
    netif->stats[pkt->stack_idx].omcasts++;

    IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCOutMcastPkts, 1);
    IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCOutMcastPkts, 1, netif, pkt->stack_idx);
    /* coverity[check_return] */
    IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCOutMcastOctets, ipcom_pkt_get_length(pkt));
    /* coverity[check_return] */
    IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCOutMcastOctets, ipcom_pkt_get_length(pkt), netif, pkt->stack_idx);

    return ipnet_ip4_local_tx(dst, pkt);
}



/*
 *===========================================================================
 *                           ipnet_ip4_bcast_tx
 *===========================================================================
 * Description: Transmits a broadcast packet.
 * Parameters:  dst - destination cache entry
 *              pkt - packet received
 * Returns:     0 = success
 *             <0 = error code
 *
 */
IP_STATIC int
ipnet_ip4_bcast_tx(Ipnet_dst_cache *dst, Ipcom_pkt *pkt)
{
#ifdef IPCOM_USE_MIB2
    Ipnet_data *net = ipnet_pkt_get_stack_instance(pkt);
#endif

    ipnet_ip4_loop_pkt_tx(dst, pkt, ipnet_ip4_dst_cache_local_tx_ctor);

    IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCOutBcastPkts, 1);
    IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCOutBcastPkts, 1, dst->neigh->netif, pkt->stack_idx);

    return ipnet_ip4_local_tx(dst, pkt);
}


#ifdef IPNET_IS_ROUTER
/*
 *===========================================================================
 *                       ipnet_ip4_forward_rx
 *===========================================================================
 * Description: Receives and forward an IP datagram.
 * Parameters:  dst - destination cache entry to use
 *              pkt - packet to prepare for forwarding
 * Returns:     0 = success
 *             <0 = error code
 *
 */
IP_STATIC int
ipnet_ip4_forward_rx(Ipnet_dst_cache *dst, Ipcom_pkt *pkt)
{
    Ipnet_ip4_layer_info *ip4_info;
    const Ipnet_pkt_ip   *ip_hdr;
#if defined(IPNET_USE_NAT) || defined(IPFIREWALL) || defined(IPIPSEC2)
    int                   ret;
#endif
    struct Ipnet_ip4_sock_opts opts;
#ifdef IPCOM_USE_MIB2
    Ipnet_data *net = ipnet_pkt_get_stack_instance(pkt);
#endif

    /* Do not forward packets received as link-level broadcast unless permitted... */
    if (IP_UNLIKELY(IP_BIT_ISSET(pkt->flags, IPCOM_PKT_FLAG_LINK_BROADCAST) &&
                    (dst->ingress_netif == IP_NULL /* ? */ ||
                     dst->ingress_netif->conf.inet.dont_forward_broadcast)))
    {
        ipcom_pkt_free(pkt);
        return -IP_ERRNO_EPERM; /* what errno is appropriate? */
    }

    IPNET_DEBUG_LINE(ip_assert(IPCOM_GET_PKT_ID(pkt) != IPCOM_PKT_ID_FREEQ));
    IPNET_DEBUG_LINE(ip_assert(IPCOM_GET_PKT_ID(pkt) != IPCOM_PKT_ID_INQ));

    IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCInForwDatagrams, 1);
    IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCInForwDatagrams, 1, dst->ingress_netif, pkt->stack_idx);

    IP_BIT_SET(pkt->flags,
               IPCOM_PKT_FLAG_FORWARDED | IPCOM_PKT_FLAG_HAS_IP_HDR);
    IP_BIT_CLR(pkt->flags,
               IPCOM_PKT_FLAG_HW_CHECKSUM);

    /*
     * Time to check Firewall
     */
#if defined(IPNET_USE_NAT) || defined(IPFIREWALL) || defined(IPIPSEC2)
    ret = ipnet_fw_nat_rx(&dst, &pkt, IP_FALSE);
    if (ret < 0)
    {
        /* Drop packet */
        ipcom_pkt_free(pkt);
        return ret;
    }
    ip_assert(ret != 1);
#endif /* defined(IPNET_USE_NAT) || defined(IPFIREWALL) || defined(IPIPSEC2) */

    ip_hdr = ipcom_pkt_get_iphdr(pkt);

    ip4_info = IPNET_IP4_GET_LAYER_INFO(pkt);
    if (IP_UNLIKELY(IP_BIT_ISSET(ip4_info->flags, IPNET_IP4_OPF_ROUTER_ALERT)))
    {
        /*
         * Send a copy of this packet to all matching socket
         */
        if (ipnet_sock_router_alert_pkt(pkt) > 0)
        {
            /*
             * Packet matched at least one socket, done processing
             * this packet.
             */
            return 0;
        }
    }

    if (IP_UNLIKELY(IPNET_IP4_GET_HDR_OCTET_LEN(ip_hdr) != IPNET_IP_HDR_SIZE))
    {
        opts.len = IPNET_IP4_GET_OPTS_OCTET_LEN(ip_hdr);
        if (opts.len < 0)
        {
            /* Invalid packet */
            ipcom_pkt_free(pkt);
            return -IP_ERRNO_EINVAL;
        }
        ipcom_memcpy(opts.opts, ip_hdr + 1, opts.len);
        ip4_info->opts = &opts;
    }

    /*
     * Store the fragment offset of this packet, if it is a fragment.
     */
    if (IPNET_ISFRAG(ip_hdr->off))
        pkt->offset = ipnet_ip4_get_offset(pkt);
    else
        pkt->offset = 0;

    if (IP_BIT_ISSET(ip_hdr->off, IPNET_OFF_DF))
        IP_BIT_SET(ip4_info->flags, IPNET_IP4_OPF_DONT_FRAG);

#ifdef IPNET_USE_DIFFSERV
    /*
     * Classifier, meter and marker step. Marker might change the DS
     * field, which would change the 'dst' instance.
     */
    dst = ipnet_diffserv_input(dst, pkt, ipnet_ip4_dst_cache_rx_ctor);
#endif /* IPNET_USE_DIFFSERV */

    return ipnet_dst_cache_tx(dst,  pkt);
}



/*
 *===========================================================================
 *                           ipnet_ip4_forward_tx
 *===========================================================================
 * Description: Transmits a packet that has been forwarded by this node.
 * Parameters:  dst - destination cache entry to use
 *              pkt - packet to transmit
 * Returns:     0 = success
 *             <0 = error code
 *
 */
IP_STATIC int
ipnet_ip4_forward_tx(Ipnet_dst_cache *dst, Ipcom_pkt *pkt)
{
    int           pkt_len = ipcom_pkt_get_length(pkt);
    int           ret;
    Ipnet_pkt_ip *ip_hdr;
    Ipnet_netif  *netif = dst->neigh->netif;
    Ipnet_data *net = ipnet_pkt_get_stack_instance(pkt);

    IPCOM_PKT_TRACE(pkt, IPCOM_PKT_ID_IP4_OUTPUT);
    IPNET_DEBUG_LINE(ipnet_pkt_check(pkt));

    ip_hdr = ipcom_pkt_get_iphdr(pkt);

#ifdef IPIPSEC2
    /* Keep ingress ifindex if case IPsec cause packet to become larger than
     * next hop MTU. May be required to send ICMP Destination Unreachable,
     * Fragmentation needed */
    ipcom_pkt_set_info(pkt, IPNET_PKT_INFO_INGRESS_IFINDEX, sizeof(unsigned), &(pkt->ifindex));
#endif

    /*
     * Set pkt->ifindex to the egress network interface.
     */
    pkt->ifindex = netif->ipcom.ifindex;

    /*
     * Check the TTL before we check if the packet needs to be
     * fragmented. This is to avoid sending one ICMP message per
     * fragment  if TTL is too small.
     */
    if (IP_UNLIKELY(ip_hdr->ttl <= 1))
    {
        Ipnet_icmp_param icmp_param;

        /*
         * The time to live field reached 0, send a time exceeded
         * message
         */
        ipnet_icmp4_param_init(&icmp_param, pkt);
        icmp_param.type = IPNET_ICMP4_TYPE_TIME_EXCEEDED;
        icmp_param.code = IPNET_ICMP4_CODE_TIM_TTL;
        ret = ipnet_icmp4_send(&icmp_param, IP_FALSE);
        IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_INFO,
                          1, 38, IPCOM_WV_NETDEVENT_INFO, IPCOM_WV_NETD_RECV,
                          ipnet_ip4_forward_tx, IPCOM_WV_NETD_INFO_TIMEOUT,
                          IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
        IPNET_STATS(net, ip4_input_time_exceeded++);
        IPCOM_MIB2(net, ipInHdrErrors++);
        IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsInHdrErrors, 1);
        IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsInHdrErrors, 1, netif, pkt->stack_idx);
        goto errout;
    }

    /*
     * Decrease the TTL by one and recalculate the checksum.
     */
    IP_INCREMENTAL_CHECKSUM(ip_hdr);

    /*
     * Time to check Firewall, NAT and IPSEC
     */
#if defined(IPNET_USE_NAT) || defined(IPFIREWALL) || defined(IPIPSEC2)
    ret = ipnet_fw_nat_ipsec_tx(&dst, &pkt, IP_TRUE);
    if (ret < 0)
    {
        /* Drop packet */
        goto errout;
    }
    else if (ret > 0)
    {
        /* Packet absorbed */
        return 0;
    }
    else
    {
        Ipnet_ip4_layer_info *ip4_info;

        /* OK */
        pkt_len = ipcom_pkt_get_length(pkt);
        ip_hdr = ipcom_pkt_get_iphdr(pkt);

        ip4_info = IPNET_IP4_GET_LAYER_INFO(pkt);
        ip4_info->proto = ip_hdr->p;
    }

    /*
     * Set pkt->ifindex to the egress network interface.
     * NAT/FW/IPSEC may change dst cache entry
     */
    netif = dst->neigh->netif;
    pkt->ifindex = netif->ipcom.ifindex;

#endif /* defined(IPNET_USE_NAT) || defined(IPFIREWALL) || defined(IPIPSEC2) */


    if (IP_UNLIKELY(dst->path_mtu < (unsigned) pkt_len))
    {
        /*
         * Must fragment this IP datagram before transmission.
         */
        if (IP_BIT_ISSET(ip_hdr->off, IPNET_OFF_MF))
            IP_BIT_SET(pkt->flags, IPCOM_PKT_FLAG_FRAGMENT);

        /*
         * Increment TTL to avoid decrementing twice.
         */
        ip_hdr->ttl++;
        ip_hdr->sum = 0;
        ip_hdr->sum = ipcom_in_checksum(ip_hdr, (Ip_size_t)IPNET_IP4_GET_HDR_OCTET_LEN(ip_hdr));

        return ipnet_ip4_frag_tx(dst, pkt, ipnet_ip4_forward_tx);
    }

    IPCOM_MIB2(net, ipForwDatagrams++);
    IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCOutForwDatagrams, 1);
    IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCOutForwDatagrams, 1, netif, pkt->stack_idx);
    IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCOutTransmits, 1);
    IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCOutTransmits, 1, netif, pkt->stack_idx);
    IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCOutOctets, pkt_len);
    IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCOutOctets, pkt_len, netif, pkt->stack_idx);


#ifdef IPROHC
    if (iprohc.opened
        && (netif->ipcom.type != IP_IFT_TUNNEL))
    {
        /*
         * Do ROHC on a not (TUNNEL) interface 
         */
        ret = iprohc_output_hook(&netif->ipcom, pkt);
        if (ret != IPCOM_SUCCESS)
        {
            /* ROHC failed */
            IPCOM_LOG1(WARNING, "Discarding IPv4 datagram on %s, ROHC failed.", netif->ipcom.name);
            ret = IPNET_ERRNO(EROHC);
            goto errout;
        }
    }
#endif /* IPROHC */

    return ipnet_neigh_tx(dst->neigh, dst, pkt);

 errout:
    ipcom_pkt_free(pkt);
    return ret;
}



/*
 *===========================================================================
 *                         ipnet_ip4_do_redirect
 *===========================================================================
 * Description: Handles the case where the source node might just as well
 *              send the IP-datagram directly to the destination node
 *              instead of going through this router node.
 * Parameters:  dst - destination cache entry
 *              pkt - an IP-datagram
 * Returns:
 *
 */
IP_STATIC int
ipnet_ip4_do_redirect(Ipnet_dst_cache *dst, Ipcom_pkt *pkt)
{
#if defined(IPCOM_FORWARDER_NAE)
    IPCOM_UNUSED_ARG(dst);

    IPCOM_LOG2(DEBUG2,
               "ipnet_ip4_do_redirect() :: datagram (%s to %s) passed to master os",
               ipcom_inet_ntop(IP_AF_INET,
                               &dst->flow_spec.from,
                               dst->net->log_buf,
                               sizeof(dst->net->log_buf)),
               ipcom_inet_ntop(IP_AF_INET,
                               &dst->flow_spec.to,
                               dst->net->log_buf + IP_INET_ADDRSTRLEN,
                               sizeof(dst->net->log_buf)- IP_INET_ADDRSTRLEN));

    ipcom_pkt_to_master_os(pkt);
    return 0;
#else
    Ip_bool forward_pkt;
    Ip_bool send_redirect;

    /* Do not send recirect for packets received as link-level broadcast unless permitted... */
    if (IP_UNLIKELY(IP_BIT_ISSET(pkt->flags, IPCOM_PKT_FLAG_LINK_BROADCAST) &&
                   (dst->ingress_netif == IP_NULL /* ? */ ||
                    dst->ingress_netif->conf.inet.dont_forward_broadcast)))
    {
       ipcom_pkt_free(pkt);
       return -IP_ERRNO_EPERM; /* what errno is appropriate? */
    }

    switch (dst->neigh->netif->conf.inet.icmp_redirect_send)
    {
    case -1:
        forward_pkt = IP_FALSE;
        send_redirect = IP_FALSE;
        break;
    case 0:
        forward_pkt = IP_TRUE;
        send_redirect = IP_FALSE;
        break;
    case 1:
        forward_pkt = IP_FALSE;
        send_redirect = IP_TRUE;
        break;
    default:
        forward_pkt = IP_TRUE;
        send_redirect = IP_TRUE;
        break;
    }

    if (send_redirect)
    {
        Ipnet_icmp_param  icmp_param;

        ipnet_icmp4_param_init(&icmp_param, pkt);
        icmp_param.type              = IPNET_ICMP4_TYPE_REDIRECT;
        icmp_param.code              = IPNET_ICMP4_CODE_RED_HOST;
        icmp_param.data.gateway_addr = &dst->neigh->addr.in;
        (void) ipnet_icmp4_send(&icmp_param, IP_FALSE);
    }

    if (forward_pkt)
        return ipnet_ip4_forward_rx(dst, pkt);

    ipcom_pkt_free(pkt);
    return 0;
#endif /* !IPCOM_FORWARDER_NAE */
}
#endif /* IPNET_IS_ROUTER */



/*
 *===========================================================================
 *                   ipnet_ip4_is_addr_old_style_bcast
 *===========================================================================
 * Description: Returns if an address is an old style broadcast address,
 *              i.e. all bits in the host part of the address is zero.
 * Parameters:  addr - an IPv4 address
 *              addr_type - address type
 * Returns:     IP_TRUE if the address is an old style broadcast address
 *              IP_FALSE otherwise
 *
 */
IP_STATIC Ip_bool
ipnet_ip4_is_addr_old_style_bcast(IP_CONST struct Ip_in_addr *addr,
                                  enum Ipnet_addr_type addr_type)
{
    return addr_type == IPNET_ADDR_TYPE_NETBROADCAST
        && (ip_htonl(addr->s_addr) & 1) == 0;
}



/*
 *===========================================================================
 *                  ipnet_ip4_dst_cache_local_tx_ctor
 *===========================================================================
 * Description: Creates a new destinatination cache entry for a flow
 *              that originates from this node. The flow information
 *              has been added to the entry at this point. This
 *              function must select a local IP address, and input and
 *              output handlers.
 * Parameters:  dst - a destination cache entry.
 *              rt_to_dst - FIB entry matching the final destination
 * Returns:     0 = success
 *              0< = error code
 *
 */
IP_STATIC int
ipnet_ip4_dst_cache_local_tx_ctor(Ipnet_dst_cache *dst,
                                  Ipnet_route_entry *rt_to_dst)
{
    Ipnet_flow_spec     *flow_spec = &dst->flow_spec;
    Ip_u16               vr = flow_spec->vr;
    struct Ip_in_addr    to = flow_spec->to.in;
    struct Ip_in_addr    from = flow_spec->from.in;
    Ipnet_route_entry   *rt;
    enum Ipnet_addr_type from_type;

    if (IP_BIT_ISFALSE(rt_to_dst->hdr.flags, IPNET_RTF_GATEWAY))
        /*
         * Not going through a gateway.
         */
        rt = rt_to_dst;
    else
    {
        int                    ret;
        struct Ip_sockaddr_in *gw;

        gw = (struct Ip_sockaddr_in *) rt_to_dst->gateway;

        if (IP_UNLIKELY(gw->sin_addr.s_addr == to.s_addr)
            && IP_BIT_ISSET(rt_to_dst->hdr.flags, IPNET_RTF_HOST)
            && to.s_addr == IPNET_IP4_GET_IPADDR(rt_to_dst->hdr.key))
            rt = rt_to_dst;
        else
        {
            /* Note, this routine is called with the routing lock already held */
            ret = ipnet_route_lookup_l(IP_AF_INET,
                                       vr,
                                       IPNET_ROUTE_GET_TABLE(rt_to_dst->head),
                                       0,
                                       &gw->sin_addr,
                                       flow_spec->zone_id,
                                       rt_to_dst->netif->ipcom.ifindex,
                                       &rt);
            if (ret < 0)
                return ret;

            while (IP_BIT_ISSET(rt->hdr.flags, IPNET_RTF_GATEWAY)
                   && rt->next != IP_NULL)
                rt = rt->next;

            if (IP_BIT_ISSET(rt->hdr.flags, IPNET_RTF_GATEWAY))
            {
                /*
                 * Needs to go through a gateway to reach the gateway,
                 * this means that we cannot reach the destination.
                 */
                return (IP_BIT_ISSET(rt_to_dst->hdr.flags, IPNET_RTF_HOST)
                        ? IPNET_ERRNO(EHOSTUNREACH)
                        : IPNET_ERRNO(ENETUNREACH));
            }
        }
    }

    /*
     * Determine the type of the destination address
     */
    if (IP_IN_CLASSD(to.s_addr))
        dst->to_type = IPNET_ADDR_TYPE_MULTICAST;
    else
    {
        dst->to_type = ipnet_ip4_get_addr_type(to.s_addr,
                                               vr,
                                               IP_NULL);
        if (dst->to_type == IPNET_ADDR_TYPE_NOT_LOCAL)
        {
            /* Check if it is network or subnetwork broadcast */
            Ip_u32       i;
            Ipnet_netif *netif;

            /* coverity[result_independent_of_operands] */
            IPNET_NETIF_FOR_EACH(netif, i)
            {
                dst->to_type = ipnet_ip4_get_addr_type(to.s_addr,
                                                       vr,
                                                       netif);
                if (dst->to_type != IPNET_ADDR_TYPE_NOT_LOCAL)
                    break;
            }
        }
    }


    /*
     * Determine the local address to use
     */
    if (IP_IN_CLASSD(from.s_addr))
        /*
         * Will happen if sending packets from a socket that is bound
         * to a multicast address.
         */
        from_type = IPNET_ADDR_TYPE_MULTICAST;
    else
        from_type = ipnet_ip4_get_addr_type(from.s_addr,
                                            vr,
                                            IP_NULL);
    if (from_type == IPNET_ADDR_TYPE_UNICAST
        || from_type == IPNET_ADDR_TYPE_NOT_LOCAL)
    {
        /*
         * The from address is not the any-address, multicast or
         * broadcast address.
         */
        dst->laddr.in = from;
    }
    else
    {
        const struct Ip_in_addr *laddr;
        Ipnet_netif             *netif;

        netif = ipnet_if_indextonetif(vr,
                                      dst->flow_spec.egress_ifindex);
        laddr = ipnet_ip4_get_src_addr(vr,
                                       &to,
                                       rt,
                                       netif);

        if (laddr == IP_NULL)
            /*
             * This would only happen during startup before any
             * addres has been assigned to this node.
             */
            dst->laddr.in = ip_inaddr_any;
        else
            dst->laddr.in = *laddr;
    }


    if (ipnet_ip4_is_addr_old_style_bcast(&dst->flow_spec.to.in,
                                          dst->to_type))
    {
        /*
         * Sending to old style broadcast address. RFC 1812 chapter
         * 4.2.3.1 state that:
         *
         * SHOULD NOT originate datagrams addressed to 0.0.0.0 or {
         * <Network-prefix>, 0 }.  There MAY be a configuration option
         * to allow generation of these packets (instead of using the
         * relevant 1s format broadcast).  This option SHOULD default
         * to not generating them.
         */
    	/*WRKK246189*/
		#ifdef WRKK246189_OLDSTYLEBCAST
    		dst->to_type = IPNET_ADDR_TYPE_NETBROADCAST;
		#else
    		return IPNET_ERRNO(EHOSTUNREACH);
		#endif       
    }


    /*
     * Set transmission handler for this flow
     */
    switch (dst->to_type)
    {
    case IPNET_ADDR_TYPE_MULTICAST:
        ipnet_dst_cache_set_tx_handler(dst, ipnet_ip4_mcast_tx);
        break;
    case IPNET_ADDR_TYPE_BROADCAST:
    case IPNET_ADDR_TYPE_NETBROADCAST:
        ipnet_dst_cache_set_tx_handler(dst, ipnet_ip4_bcast_tx);
        break;
    default:
        ipnet_dst_cache_set_tx_handler(dst, ipnet_ip4_local_tx);
        break;
    }

    /*
     * Set reception handler for this flow
     */
    switch (dst->to_type)
    {
    case IPNET_ADDR_TYPE_UNICAST:
    case IPNET_ADDR_TYPE_BROADCAST:
    case IPNET_ADDR_TYPE_NETBROADCAST:
    case IPNET_ADDR_TYPE_TENTATIVE:
        /*
         * One of the local addresses on this node, this entry might
         * be used by datagrams received. Those datagrams should be
         * delivered locally
         */
        ipnet_dst_cache_set_rx_handler(dst, ipnet_ip4_local_rx);
        break;
    default:
        /*
         * Nothing should ever be received via this destination cache entry.
         */
        ipnet_dst_cache_set_rx_handler(dst,
                                       ipnet_dst_cache_blackhole(dst->net)->rx);
        break;
    }

    return 0;
}



/*
 *===========================================================================
 *                    ipnet_ip4_martian_addr_filtering
 *===========================================================================
 * Description: Performs Martian Address Filtering as descibed by
 *              RFC1812, chapter 5.3.7
 * Parameters:  netif - ingress interface
 *              src_n - source address of IP datagram
 *              dst_n - destination address of IP datagram
 *              dst_addr_type - type of destination address.
 * Returns:     IP_FALSE addresses failed the Martian filter and the
 *                    IP datagram should be discarded.
 *              IP_TRUE - addresses looks OK
 */
IP_STATIC Ip_bool
ipnet_ip4_martian_addr_filtering(Ipnet_netif *netif,
                                 Ip_u32 src_n,
                                 Ip_u32 dst_n,
                                 enum Ipnet_addr_type dst_addr_type)
{
    enum Ipnet_addr_type src_addr_type;

    /*
     * An IP destination address is invalid if it is among those
     * defined as illegal destinations in 4.2.3.1, or is a Class E
     * address (except 255.255.255.255).
     */
    if (dst_addr_type == IPNET_ADDR_TYPE_ANY
        || (dst_addr_type != IPNET_ADDR_TYPE_BROADCAST
            && IP_IN_BADCLASS(dst_n)))
        return IP_FALSE;

    if (IP_BIT_ISFALSE(netif->ipcom.flags, IP_IFF_LOOPBACK))
    {
        /*
         * A router SHOULD NOT forward, except over a loopback interface,
         * any packet that has a source address on network 127.
         */
        if ((*(Ip_u8*) &src_n) == 127)
            return IP_FALSE;

        /*
         * A router SHOULD NOT forward, except over a loopback interface,
         * any packet that has a destination address on network 127.
         */
        if ((*(Ip_u8*) &dst_n) == 127)
            return IP_FALSE;
    }

    /*
     * If not not local, this packet is destined for this host - skip
     * router sanity
     */
    if (dst_addr_type != IPNET_ADDR_TYPE_NOT_LOCAL || IP_IN_CLASSD(dst_n))
        return IP_TRUE;

    /*
     * A router SHOULD NOT forward any packet that has an invalid IP
     * source address or a source address on network 0.
     */
    src_addr_type = ipnet_ip4_get_addr_type(src_n,
                                            netif->vr_index,
                                            netif);
    return (!IP_IN_CLASSD(src_n)
            && !IP_IN_BADCLASS(src_n)
            && (src_addr_type == IPNET_ADDR_TYPE_UNICAST
                || src_addr_type == IPNET_ADDR_TYPE_NOT_LOCAL));
}



/*
 *===========================================================================
 *                     ipnet_ip4_src_addr_validation_rtl
 *===========================================================================
 * Description: Verifies that the source address would be reached
 *              through the passed network interface.
 * Parameters:  netif - ingress interface for IP-datafram with source
 *                     'src_n'
 *              src_n - an IP address
 * Returns:     IP_TRUE - correct interface
 *              IP_FALSE - wrong interface.
 *
 */
#ifdef IPNET_USE_RFC1812_SRC_ADDR_VALIDATION
IP_STATIC Ip_bool
ipnet_ip4_src_addr_validation_rtl(Ipnet_netif *netif, Ip_u32 src_n)
{
    Ipnet_route_entry *rt;
    int ret;

    /*
     * RFC 1812, chapter 5.3.8
     * If this filtering is enabled, the router MUST silently discard
     * a packet if the interface on which the packet was received is
     * not the interface on which a packet would be forwarded to reach
     * the address contained in the source address.  In simpler terms,
     * if a router wouldn't route a packet containing this address
     * through a particular interface, it shouldn't believe the
     * address if it appears as a source address in a packet read from
     * this interface.
     *
     * NOTE: this routine is called only from ipnet_ip4_dst_cache_rx_ctor(),
     * which is called with the route table lock already held.
     */
    ret = ipnet_route_lookup_l(IP_AF_INET,
                                netif->vr_index,
                                IPCOM_ROUTE_TABLE_DEFAULT,
                                0,
                                &src_n,
                                0,
                                netif->ipcom.ifindex,
                                &rt);

    return ret >= 0;
}
#endif /* IPNET_USE_RFC1812_SRC_ADDR_VALIDATION */


/*
 *===========================================================================
 *                ipnet_ip4_get_local_addr_on_same_subnet
 *===========================================================================
 * Description: Returns the local address on the specified interface
 *              that is located on the same subnet as the passed address.
 * Parameters:
 *              inaddr - an IP address
 *              netif - a network interface
 * Returns:     The matching local address or IP_NULL if nothing matches.
 *
 */
IP_STATIC struct Ip_in_addr *
ipnet_ip4_get_local_addr_on_same_subnet(const struct Ip_in_addr *inaddr,
                                        Ipnet_netif             *netif,
                                        Ip_src_addr_filter       filter,
                                        void *                   filter_arg)
{
    Ipnet_ip4_addr_entry *addr;

    if (netif != IP_NULL)
        for (addr = netif->inet4_addr_list; addr != IP_NULL; addr = addr->next)
        {
            if (addr->type != IPNET_ADDR_TYPE_UNICAST)
                /*
                 * No more unicast address available on this interface
                 */
                break;

            if ((ipcom_route_key_cmp(32,
                                    inaddr,
                                    &addr->ipaddr_n,
                                    &addr->netmask_n))
#ifdef IPNET_USE_RFC5227
                  /* Should not use a tentative address */
                  && (!IP_BIT_ISSET(addr->flags, IPNET_IP4_ADDR_FLAG_TENTATIVE))
#endif
                )
            {
                /*
                 * This address is located on the same subnet as the
                 * destination address of the IP-datagram that caused
                 * this ICMP nessage to be sent.
                 */
                if (filter == IP_NULL ||
                    filter(&addr->ipaddr_n, IP_AF_INET, 0, filter_arg))
                    return (struct Ip_in_addr *) &addr->ipaddr_n;
            }
        }

    return IP_NULL;
}


/*
 *===========================================================================
 *                      ipnet_ip4_is_on_same_subnet
 *===========================================================================
 * Description: Checks if "from" and "to" is located on the same subnet
 *              and if that subnet is link-local to "netif".
 * Parameters:  netif - Egress interface
 *              pfrom - sender of the packet
 *              pto - address of the next hop
 * Returns:     IP_TRUE if the sender should be able to directly reach
 *              the next hop.
 *
 */
#ifdef IPNET_IS_ROUTER
IP_STATIC Ip_bool
ipnet_ip4_is_on_same_subnet(Ipnet_netif *netif,
                            IP_CONST struct Ip_in_addr *pfrom,
                            IP_CONST struct Ip_in_addr *pto)
{
    Ipnet_ip4_addr_entry *addr;
    Ip_u32                from_n;
    Ip_u32                to_n;

    from_n = IPNET_IP4_GET_IPADDR((void *)pfrom);
    to_n = IPNET_IP4_GET_IPADDR((void *)pto);

    for (addr = netif->inet4_addr_list; addr != IP_NULL; addr = addr->next)
    {
        Ip_u32 net_n = addr->ipaddr_n & addr->netmask_n;

        if (net_n == (from_n & addr->netmask_n))
            return net_n == (to_n & addr->netmask_n);
    }

    return IP_FALSE;
}
#endif /* IPNET_IS_ROUTER */



/*
 *===========================================================================
 *                  ipnet_ip4_dst_cache_rx_ctor
 *===========================================================================
 * Description: Creates a destination cache entry that will be used
 *              for ingress packets.
 * Parameters:  dst - a destination cache entry.
 *              rt - FIB entry used for this destination cache entry.
 * Returns:     0 = success
 *              0< = error code
 *
 */
IP_GLOBAL int
ipnet_ip4_dst_cache_rx_ctor(Ipnet_dst_cache *dst,
                            Ipnet_route_entry *rt)
{
    enum Ipnet_addr_type from_type;
    Ipnet_dst_cache     *dst_blackhole;
    Ipnet_flow_spec     *flow_spec = &dst->flow_spec;
    Ipnet_netif         *netif = rt->netif;
    Ipnet_data          *net = dst->net;

    /*
     * Flows that should be discarded are done so by setting the RX
     * handler to be the RX hander of the blackhole entry.
     */
    dst_blackhole = ipnet_dst_cache_blackhole(net);

   /*
     * "local" address of ingress packets is always the same as the
     * 'from' address. It is done this way so that an IP header can
     * always use the 'laddr' in the source field.
     */
    dst->laddr = flow_spec->from;

    /*
     * Determine what kind of address type this flow is targeted to.
     */
    if (dst->ingress_netif == IP_NULL)
        dst->to_type = ipnet_ip4_get_addr_type(flow_spec->to.in.s_addr,
                                               flow_spec->vr,
                                               netif);
    else
    {
        dst->to_type = ipnet_ip4_get_addr_type(flow_spec->to.in.s_addr,
                                               flow_spec->vr,
                                               dst->ingress_netif);

        if (dst->to_type == IPNET_ADDR_TYPE_NOT_LOCAL)
        {
            /*
             * This will catch the case where broadcast packets has
             * been looped back.
             */
            if (IP_IN_CLASSD(flow_spec->to.in.s_addr)
                && IP_BIT_ISTRUE(dst->ingress_netif->ipcom.flags, IP_IFF_LOOPBACK))
                dst->to_type = IPNET_ADDR_TYPE_MULTICAST;
            else
                dst->to_type = ipnet_ip4_get_addr_type(flow_spec->to.in.s_addr,
                                                           flow_spec->vr,
                                                       netif);
        }
        else
            /*
             * This flow is directed to one of the local addresses.
             */
            netif = dst->ingress_netif;
    }

    if (dst->to_type == IPNET_ADDR_TYPE_NOT_LOCAL)
    {
        if (IP_BIT_ISFALSE(ipnet_shared()->flags, IPNET_FLAG_IPV4_STRICT_MODE)
            || ((dst->ingress_netif != IP_NULL)
                   && IP_BIT_ISSET(dst->ingress_netif->ipcom.flags, IP_IFF_LOOPBACK)))
            /*
                     * In strict mode, check all addresses if Rx interface is loopback. 
                     * In loose mode, always check all addresses.
                     * Might have received the packet on an interface different
                     * from the interface the address was assigned to. Check the
                     * address type again and check all interfaces this time.
                     */
            dst->to_type = ipnet_ip4_get_addr_type(flow_spec->to.in.s_addr,
                                                   flow_spec->vr,
                                                   IP_NULL);
     }

#ifdef IPNET_USE_VRRP
    if (dst->to_type == IPNET_ADDR_TYPE_NOT_LOCAL
        && ipnet_vrrp_addr_vrid(netif, &(flow_spec->to.in), IP_AF_INET))
    {
        /*
         * This node is master for this VRRP address right now
         */
        dst->to_type = IPNET_ADDR_TYPE_UNICAST;
    }
#endif

    /*
     * Determine what kind of address type the flow is sent from.
     */
    from_type = ipnet_ip4_get_addr_type(dst->flow_spec.from.in.s_addr,
                                        dst->flow_spec.vr,
                                        IP_NULL);

    if (from_type == IPNET_ADDR_TYPE_UNICAST
        || from_type == IPNET_ADDR_TYPE_TENTATIVE)
        /*
         * Might be used in the reversed direction when this node
         * sends datagrams.
         */
        ipnet_dst_cache_set_tx_handler(dst, ipnet_ip4_local_tx);
    else
        /*
         * Default to drop anything sent via this flow, might be
         * changed to allow forwarding further down in this function.
         */
        ipnet_dst_cache_set_tx_handler(dst, dst_blackhole->tx);

    if (dst->ingress_netif != IP_NULL
        && !ipnet_ip4_martian_addr_filtering(dst->ingress_netif,
                                          dst->flow_spec.from.in.s_addr,
                                          dst->flow_spec.to.in.s_addr,
                                          dst->to_type))
    {
        /*
         * RFC 1812, chapter 5.3.7
         *
         * If a router discards a packet because of these rules, it
         * SHOULD log at least the IP source address, the IP
         * destination address, and, if the problem was with the
         * source address, the physical interface on which the packet
         * was received and the Link Layer address of the host or
         * router from which the packet was received.
         */
        IPCOM_LOG3(NOTICE,
                   "Discarding IP datagram from %s to %s on %s since it failed Martian filtering",
                   ipcom_inet_ntop(IP_AF_INET,
                                   &dst->flow_spec.from,
                                   net->log_buf,
                                   sizeof(net->log_buf)),
                   ipcom_inet_ntop(IP_AF_INET,
                                   &dst->flow_spec.to,
                                   net->log_buf + IP_INET_ADDRSTRLEN,
                                   sizeof(net->log_buf)- IP_INET_ADDRSTRLEN),
                   netif->ipcom.name);
        ipnet_dst_cache_set_rx_handler(dst, dst_blackhole->rx);
    }
    else if (ipnet_ip4_is_addr_old_style_bcast(&dst->flow_spec.to.in,
                                               dst->to_type))
    {
        /*
         * Packet to old style broadcast address. Processing of such
         * address is described in RFC1812 chapter 4.2.3.1:
         *
         * SHOULD silently discard on receipt (i.e., do not even
         * deliver to applications in the router) any packet addressed
         * to 0.0.0.0 or { <Network-prefix>, 0 }.  If these packets
         * are not silently discarded, they MUST be treated as IP
         * broadcasts (see Section [5.3.5]).  There MAY be a
         * configuration option to allow receipt of these packets.
         * This option SHOULD default to discarding them.
         */
    	/*WRKK246189*/
		#ifdef WRKK246189_OLDSTYLEBCAST
			dst->to_type = IPNET_ADDR_TYPE_NETBROADCAST;
			ipnet_dst_cache_set_rx_handler(dst, ipnet_ip4_bcast_rx);    	
		#else
        	ipnet_dst_cache_set_rx_handler(dst, dst_blackhole->rx);
		#endif
    }
#ifdef IPNET_USE_RFC1812_SRC_ADDR_VALIDATION
    else if (!ipnet_ip4_src_addr_validation_rtl((dst->ingress_netif
                                                 ? dst->ingress_netif
                                                 : netif),
                                                dst->flow_spec.from.in.s_addr))
    {
        /*
         * Source address validation as described in RFC 1812, chapter
         * 5.3.8 failed.
         */
        ipnet_dst_cache_set_rx_handler(dst, dst_blackhole->rx);
    }
#endif /* IPNET_USE_RFC1812_SRC_ADDR_VALIDATION */
    else
    {
        /*
         * Source and destination IP address passed sanity tests.
         */
        if (dst->to_type == IPNET_ADDR_TYPE_UNICAST
            || dst->to_type == IPNET_ADDR_TYPE_TENTATIVE)
        {
            ipnet_dst_cache_set_rx_handler(dst, ipnet_ip4_local_rx);
        }
        else if ((dst->to_type == IPNET_ADDR_TYPE_BROADCAST
                  || dst->to_type == IPNET_ADDR_TYPE_NETBROADCAST)
                 && (netif->ipcom.ifindex == dst->flow_spec.ingress_ifindex
                     || (dst->ingress_netif &&
                         IP_BIT_ISSET(dst->ingress_netif->ipcom.flags, IP_IFF_LOOPBACK))))
        {
            /*
             * Broadcasts is only accepted if received via loopback or
             * on the ingress interface.
             */
            ipnet_dst_cache_set_rx_handler(dst, ipnet_ip4_bcast_rx);
        }
        else if (IP_IN_CLASSD(dst->flow_spec.to.in.s_addr))
        {
            /*
             * All multicast addresses, regardless if this node listen to
             * it or not, is handled by ipnet_ip4_mcast_rx().
             */
            ipnet_dst_cache_set_rx_handler(dst, ipnet_ip4_mcast_rx);
            ipnet_dst_cache_set_tx_handler(dst, ipnet_ip4_mcast_tx);
        }
        else
        {
#ifdef IPNET_IS_ROUTER
            if (IP_BIT_ISSET(ipnet_shared()->flags, IPNET_FLAG_IPV4_STRICT_MODE))
            {
                if (ipnet_ip4_get_addr_type(flow_spec->to.in.s_addr, flow_spec->vr, IP_NULL)
                    != IPNET_ADDR_TYPE_NOT_LOCAL)
                {
                    /* Destination address is local, but not on this interface. Do not route packets to ourselves */
                    ipnet_dst_cache_set_rx_handler(dst, dst_blackhole->rx);
                    return 0;
                }
            }

            if (IP_BIT_ISSET(ipnet_shared()->flags, IPNET_FLAG_IPV4_FORWARD_PKT)
                && (dst->ingress_netif == IP_NULL ||
                    IP_BIT_ISFALSE(dst->ingress_netif->flags2, IPNET_IFF2_NO_IPV4_FORWARD))
                && IP_BIT_ISFALSE(netif->flags2, IPNET_IFF2_NO_IPV4_FORWARD)
                && ((dst->to_type != IPNET_ADDR_TYPE_BROADCAST
                     && dst->to_type != IPNET_ADDR_TYPE_NETBROADCAST)
                    || netif->conf.inet.dont_forward_broadcast == IP_FALSE))
            {
                struct Ip_in_addr *next_hop;

                if (IP_BIT_ISFALSE(IPNET_RTF_GATEWAY, rt->hdr.flags))
                    next_hop = &flow_spec->to.in;
                else
                    next_hop = &((struct Ip_sockaddr_in *) rt->gateway)->sin_addr;

                ipnet_dst_cache_set_tx_handler(dst, ipnet_ip4_forward_tx);
                if (dst->flow_spec.ingress_ifindex == netif->ipcom.ifindex
                    && ipnet_ip4_is_on_same_subnet(netif,
                                                   &dst->flow_spec.from.in,
                                                   next_hop))
                    /*
                     * The sender should be able to directly go to the
                     * next hop node.
                     */
                    ipnet_dst_cache_set_rx_handler(dst, ipnet_ip4_do_redirect);
                else
                {
                    /*
                     * Forward flow since the current policy allows
                     * forwarding of packets to the selected egress
                     * interface.
                     */
                    ipnet_dst_cache_set_rx_handler(dst, ipnet_ip4_forward_rx);
                }
            }
            else
#endif /* IPNET_IS_ROUTER */
            {
#if 0
                /*
                 * Forwarding disabled. Discard all packets to this flow
                 */
                ipnet_dst_cache_set_rx_handler(dst, dst_blackhole->rx);
#else
                /*
                 * As a temporary solution to V7NET-727, to prevent ARPing
                 * for the destination address on the egress interface,
                 * we return an error here.  Note that this fixes the immediate
                 * issue, but wastes all the work needed to lookup the flow and
                 * create <dst>. Moreover, future packets in the same (bad)
                 * flow will have to repeat that work. So, we hope for a better
                 * solution in the future.
                 */
                return -IP_ERRNO_EHOSTUNREACH;
#endif
            }
        }
    }

    return 0;
}



/*
 *===========================================================================
 *                     ipnet_ip4_flow_spec_from_sock
 *===========================================================================
 * Description: Initializes the IPv4 portion of the flow specification.
 * Parameters:  flow_spec - buffer where the flow specification must
 *                     be stored
 *              sock - socket from where the information should be
 *                     extracted
 *              msg_ptr - pointer to user message structure or IP_NULL.
 * Returns:      0 = success
 *              <0 = error code
 *
 */
IP_STATIC int
ipnet_ip4_flow_spec_from_sock(Ipnet_flow_spec *flow_spec,
                              Ipnet_socket *sock,
                              const void *msg_ptr)
{
    Ipnet_ip4_socket *sock_ip4 = sock->ip4;
    IP_CONST struct Ip_msghdr *msg = msg_ptr;

    /*
     * Set the 'to' address
     */
    if (IP_BIT_ISSET(sock->flags, IPNET_SOCKET_FLAG_CONNECTED | IPNET_SOCKET_FLAG_CONNECTING))
        flow_spec->to.in.s_addr = sock_ip4->daddr_n;
    else
    {
        if (IP_UNLIKELY(msg == IP_NULL || msg->msg_name == IP_NULL))
            return IPNET_ERRNO(ENOTCONN);

        flow_spec->to.in = ((struct Ip_sockaddr_in *) msg->msg_name)->sin_addr;
        if (flow_spec->to.in.s_addr == IP_INADDR_ANY)
            return IPNET_ERRNO(ENETUNREACH);
    }

    /*
     * Don't route entry?
     */
    if (IP_UNLIKELY(IP_BIT_ISSET(sock->flags, IPNET_SOCKET_FLAG_DONTROUTE)))
        IP_BIT_SET(flow_spec->flags, IPNET_FSF_DONTROUTE);

    /*
     * Set the 'from' address
     */
    flow_spec->from.in.s_addr = sock_ip4->saddr_n;

    /*
     * Set TOS field
     */
    flow_spec->ds = sock_ip4->type_of_service;


    /*
     * Use specific interface?
     */
    if (sock->bind_to_ifindex != 0)
        /*
         * Bound to a specific device
         */
        flow_spec->egress_ifindex = sock->bind_to_ifindex;
    else if (sock_ip4->multicast_if != 0 && IP_IN_CLASSD(flow_spec->to.in.s_addr))
        /*
         * A specific interface was set with IP_IP_MULTICAST_IF socket
         * option
         */
        flow_spec->egress_ifindex = sock_ip4->multicast_if;
    else
        flow_spec->egress_ifindex = 0;

    /*
     * This flow will never be used for ingress traffic.
     */
    flow_spec->ingress_ifindex = 0;

    /*
     * Zone-ID is always 0 for IPv4
     */
    flow_spec->zone_id = 0;

    return 0;
}


/*
 *===========================================================================
 *                     ipnet_ip4_flow_spec_from_info
 *===========================================================================
 * Description: Initializes the IPv4 portion of the flow specification.
 * Parameters:  flow_spec - buffer where the flow specification must
 *                          be stored
 *              src - source/from IPv4 address in packet
 *              dst - destination/to IPv4 address in packet
 * Returns:      0 = success
 *              <0 = error code
 *
 */
IP_GLOBAL int
ipnet_ip4_flow_spec_from_info(Ipnet_flow_spec *flow_spec,
                              const void        *src,
                              const void        *dst)
{
    flow_spec->from.in.s_addr   = src? IP_GET_32ON8(src) : 0;
    flow_spec->to.in.s_addr     = dst? IP_GET_32ON8(dst) : 0;
    return 0;
}


/*
 *===========================================================================
 *                      ipnet_ip4_dst_cache_get_tx
 *===========================================================================
 * Description: Returns a destination cache entry that can be used for TX
 *              that matches the specified parameters.
 * Parameters:  net - network stack instance
 *              vr - virtual router index
 *              to - address of recipient
 *              from - local address or the any address to use the
 *                     source selection rules to determine source
 *                     address.
 *              tos - TOS to use.
 *              egress_ifindex - index of the interface that must be
 *                        used as egress interface or 0 for any
 *                        interface.
 *              ingress_ifindex - index of the interface that must be
 *                        used as ingress interface or 0 for any
 *                        interface.
 * Returns:    A matching destination cache entry.
 *
 */
IP_GLOBAL Ipnet_dst_cache *
ipnet_ip4_dst_cache_get_tx(Ipnet_data *net,
                           Ip_u16 vr,
                           const struct Ip_in_addr *to,
                           const struct Ip_in_addr *from,
                           Ip_u8 tos,
                           unsigned egress_ifindex,
                           unsigned ingress_ifindex)
{
    Ipnet_flow_spec  flow_spec;
    Ipnet_dst_cache *dst;

    /*
     * Create flow specification
     */
    ipcom_memset(&flow_spec, 0, sizeof(flow_spec));
    flow_spec.vr              = vr;
    flow_spec.egress_ifindex  = egress_ifindex;
    flow_spec.ingress_ifindex = ingress_ifindex;
    flow_spec.ds              = tos;
    flow_spec.to.in           = *to;
    flow_spec.from.in         = *from;
    if (ingress_ifindex)
        flow_spec.flags       = IPNET_FSF_DONTDISCARD;

    dst = ipnet_dst_cache_get(net, &flow_spec);
    if (dst == IP_NULL)
    {
        if (0 > ipnet_dst_cache_new(net,
                                    &flow_spec,
                                    ipnet_ip4_dst_cache_local_tx_ctor,
                                    &dst))
            /*
             * Failed to create destination cache entry, not possible
             * to send any response. Let us use the blackhole destination
             * cache so the response will just be discarded; this
             * avoids a lot of tricky special cases since this
             * function can always be assumed to succeed.
             */
            dst = ipnet_dst_cache_blackhole_flow_spec(net, &flow_spec);
    }
    return dst;
}


/*
 *===========================================================================
 *                      ipnet_ip4_addr_key_func
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC unsigned
ipnet_ip4_addr_key_func(Ipnet_ip4_addr_lookup *key)
{
    return ipcom_hash_update(&key->addr,
                             ip_ssizeof(key->addr),
                             key->ifindex + (Ip_u32)(key->vr << 16));
}


/*
 *===========================================================================
 *                      ipnet_ip4_addr_obj_func
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC unsigned
ipnet_ip4_addr_obj_func(Ipnet_ip4_addr_entry *addr)
{
    Ipnet_ip4_addr_lookup key;
    Ipnet_netif          *netif = ipnet_ip4_addr_to_netif(addr);

    key.ifindex     = netif->ipcom.ifindex;
    key.vr          = netif->vr_index;
    key.addr.s_addr = addr->ipaddr_n;
    return ipnet_ip4_addr_key_func(&key);
}


/*
 *===========================================================================
 *                      ipnet_ip4_addr_cmp_func
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC Ip_bool
ipnet_ip4_addr_cmp_func(Ipnet_ip4_addr_entry *addr, Ipnet_ip4_addr_lookup *key)
{
    Ipnet_netif *netif = ipnet_ip4_addr_to_netif(addr);

    return netif->ipcom.ifindex == key->ifindex
        && addr->ipaddr_n == key->addr.s_addr
        && netif->vr_index == key->vr;
}


/*
 *===========================================================================
 *                    ipnet_ip4_addr_ignore_if_key_func
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC unsigned
ipnet_ip4_addr_ignore_if_key_func(Ipnet_ip4_addr_lookup *key)
{
    return ipcom_hash_update(&key->addr, sizeof(key->addr), key->vr);
}


/*
 *===========================================================================
 *                    ipnet_ip4_addr_ignore_if_obj_func
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC unsigned
ipnet_ip4_addr_ignore_if_obj_func(Ipnet_ip4_addr_entry *addr)
{
    Ipnet_ip4_addr_lookup key;
    Ipnet_netif          *netif = ipnet_ip4_addr_to_netif(addr);

    key.vr          = netif->vr_index;
    key.addr.s_addr = addr->ipaddr_n;
    return ipnet_ip4_addr_ignore_if_key_func(&key);
}


/*
 *===========================================================================
 *                    ipnet_ip4_addr_ignore_if_cmp_func
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC Ip_bool
ipnet_ip4_addr_ignore_if_cmp_func(Ipnet_ip4_addr_entry *addr, Ipnet_ip4_addr_lookup *key)
{
    Ipnet_netif *netif = ipnet_ip4_addr_to_netif(addr);

    return addr->ipaddr_n == key->addr.s_addr
        && netif->vr_index == key->vr;
}


/*
 *===========================================================================
 *                    ipnet_ip4_addr_to_sockaddr
 *===========================================================================
 * Description: Creates a socket address structure for the specified
 *                    IPv4 address
 * Parameters:  sin - buffer to store the socket address.
 *              in_addr_n - an IPv4 address
 * Returns:     The socket address for the specified IPv4 address.
 *
 */
IP_GLOBAL struct Ip_sockaddr *
ipnet_ip4_addr_to_sockaddr(struct Ip_sockaddr_in *sin, Ip_u32 in_addr_n)
{
    ipcom_memset(sin, 0, sizeof(struct Ip_sockaddr_in));
    sin->sin_family      = IP_AF_INET;
    IPCOM_SA_LEN_SET(sin, sizeof(struct Ip_sockaddr_in));
    sin->sin_addr.s_addr = in_addr_n;
    return (struct Ip_sockaddr *) sin;
}


/*
 *===========================================================================
 *                      ipnet_ip4_addr_neigh_changed
 *===========================================================================
 * Description: Called each time the neighbor used for answer ARP probes
 *              on the address changes its state.
 * Parameters:  neigh - the neighbor used to respond to ARP request for 'addr'
 *              hint - what kind of change was made to the neighbor
 *              addr - pointer to an IPv4 address entry
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_addr_neigh_changed(const Ipnet_neigh *neigh,
                             const enum Ipnet_neigh_observer_hint *hint,
                             Ipnet_ip4_addr_entry *addr)
{
    if (*hint == IPNET_NEIGH_NEW_STATE && neigh->state == IPNET_ND_DEAD)
        (void)ipnet_ip4_addr_init_neigh_for_arp(addr);
}


/*
 *===========================================================================
 *                   ipnet_ip4_addr_init_neigh_for_arp
 *===========================================================================
 * Description: Creates a neighbor for corresponding to the passed
 *              unicast IPv4 address. The neighbor entry is used when
 *              responding to ARP requests on the address.
 * Parameters:  addr - an IPv4 address.
 * Returns:     0 = success,
 *              -IP_ERRNO_ENOMEM = out of memory
 *
 */
IP_STATIC int
ipnet_ip4_addr_init_neigh_for_arp(Ipnet_ip4_addr_entry *addr)
{
    return ipnet_neigh_init_addr_observer(IP_AF_INET,
                                          addr,
                                          &addr->ipaddr_n,
                                          addr->netif,
                                          &addr->neigh,
                                          &addr->neigh_observer,
                                          (Ipnet_neigh_observer_action)ipnet_ip4_addr_neigh_changed);
}


/*
 *===========================================================================
 *                    ipnet_ip4_assign_addr
 *===========================================================================
 * Description: Assigns the address to the inteface (which must be UP).
 * Parameters:  addr - The address entry to assign.
 * Returns:     0 = success, <0 = error code.
 *
 */
IP_STATIC int
ipnet_ip4_assign_addr(Ipnet_ip4_addr_entry *addr)
{
    Ipnet_netif *netif = ipnet_ip4_addr_to_netif(addr);
    int          ret = 0;

    if (addr->type == IPNET_ADDR_TYPE_UNICAST
        || addr->type == IPNET_ADDR_TYPE_MULTICAST)
        /*
         * Invalidate the route cache tag since assigning this address
         * might have affects on the outcome of lookups
         */
        ipnet_dst_cache_flush(netif->vr_index, IP_AF_INET);

    ip_assert(IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_UP));

    if (addr->type == IPNET_ADDR_TYPE_MULTICAST)
    {
#ifndef IPCOM_FORWARDER_NAE
        if (addr->ipaddr_n != ip_htonl(IP_INADDR_ALLHOSTS_GROUP)
            && IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_RUNNING))
        {
            addr->mcast.filter_change_resend_count = (Ip_u8) netif->igmp_robustness_variable;
            ipnet_igmp_report_filter_change(addr);
        }
#endif
    }
    else if (addr->type == IPNET_ADDR_TYPE_UNICAST
             && addr->ipaddr_n != IP_INADDR_ANY)
    {
        Ip_bool auto_proxy_arp_enabled = netif->conf.inet.auto_proxy_arp;

        if (IP_BIT_ISFALSE(addr->flags, IPNET_IP4_ADDR_FLAG_LOOPBACK_RT))
        {
            /* Add route to loopback all packets sent to this address from this host. */
            struct Ipnet_route_add_param param;
            struct Ip_sockaddr_in        gw;

            ipcom_memset(&param, 0, sizeof(struct Ipnet_route_add_param));
            if (netif->ipcom.type == IP_IFT_LOOP)
                param.netif = netif;
            else
                param.netif = ipnet_loopback_get_netif(netif->vr_index);
            param.domain  = IP_AF_INET;
            param.vr      = netif->vr_index;
            param.table   = IPCOM_ROUTE_TABLE_DEFAULT;
            param.key     = &addr->ipaddr_n;
            param.flags   = IPNET_RTF_UP | IPNET_RTF_HOST | IPNET_RTF_DONE;
            param.gateway = ipnet_ip4_addr_to_sockaddr(&gw, addr->ipaddr_n);
            if (auto_proxy_arp_enabled)
                 IP_BIT_SET(param.flags, IPNET_RTF_PROTO2);
            ret = ipnet_route_add(&param);
            if (ret < 0)
                goto cleanup;

            IP_BIT_SET(addr->flags, IPNET_IP4_ADDR_FLAG_LOOPBACK_RT);
        }

        if (IP_BIT_ISFALSE(addr->flags, IPNET_IP4_ADDR_FLAG_NETWORK_RT)
            && addr->netmask_n != 0xffffffff)
        {
            /* Add route for the (sub)network reachable by this new address */
            struct Ipnet_route_add_param param;
            Ip_u32                       netaddr_n;
            struct Ip_sockaddr_in        local_addr;

            ipcom_memset(&param, 0, sizeof(struct Ipnet_route_add_param));
            param.domain  = IP_AF_INET;
            param.vr      = netif->vr_index;
            param.table   = IPCOM_ROUTE_TABLE_DEFAULT;
            param.netif   = netif;
            netaddr_n     = addr->ipaddr_n & addr->netmask_n;
            param.key     = &netaddr_n;
            param.netmask = &addr->netmask_n;
            param.flags   = IPNET_RTF_UP | IPNET_RTF_DONE | IPNET_RTF_MASK | IPNET_RTF_CLONING;
            if (addr->type == IPNET_ADDR_TYPE_UNICAST)
                /*
                 * The gateway field will is the default source
                 * address for packets sent to the network for this
                 * address
                 */
                param.gateway = ipnet_ip4_addr_to_sockaddr(&local_addr, addr->ipaddr_n);

            if (auto_proxy_arp_enabled)
                 IP_BIT_SET(param.flags, IPNET_RTF_PROTO2);

            ret = ipnet_route_add(&param);
            if (ret >= 0 || ret == -IP_ERRNO_EEXIST)
            {
                IP_BIT_SET(addr->flags, IPNET_IP4_ADDR_FLAG_NETWORK_RT);
                ret = 0;
            }
        }
#if defined(IPCOM_USE_ETHERNET) && !defined(IPCOM_FORWARDER_NAE)
        if (ret >= 0)
        {
            if ((netif->ipcom.type == IP_IFT_ETHER
                 || netif->ipcom.type == IP_IFT_L2VLAN
                 || netif->ipcom.type == IP_IFT_IEEE80211)
#ifdef IPBRIDGE
                 || IPBRIDGE_IFT_CHECK(netif->ipcom.type)
#endif
                )
            {
                IP_BIT_CLR(addr->flags, IPNET_IP4_ADDR_FLAG_TENTATIVE);
                ipv4AddressEventHookProcess(IP_ADDREVENT_INET_DADBEGIN, netif->ipcom.ifindex,
                                     addr->ipaddr_n, (void *)netif->ipcom.link_addr);
                if ((netif->conf.inet.send_gratuitous_arp == IP_TRUE)
#ifdef IPNET_USE_RFC5227
                    &&(netif->conf.inet.address_conflict_detect == IP_FALSE)
#endif
                    )
                {
                    /* Send gratuitous ARP request. */
                    ipnet_arp_request(netif,
                                      0,
                                      addr->ipaddr_n,
                                      IP_TRUE,
                                      IP_NULL,
                                      IP_NULL);
                }
            }
        }
#endif /* IPCOM_USE_ETHERNET && !IPCOM_FORWARDER_NAE */

        /*
         * Get the neighbor entry for this address. Must be done AFTER
         * the route entries has been added or it will fail.
         */
        ret = ipnet_ip4_addr_init_neigh_for_arp(addr);
        if (ret)
            goto cleanup;
    }

    if (IP_BIT_ISFALSE(addr->flags, IPNET_IP4_ADDR_FLAG_NEWADDR_DONE)
        && (addr->type == IPNET_ADDR_TYPE_UNICAST || addr->type == IPNET_ADDR_TYPE_MULTICAST))
    {
        IP_BIT_SET(addr->flags, IPNET_IP4_ADDR_FLAG_NEWADDR_DONE);
        ipnet_kioevent(netif, IP_EIOXNEWADDR, IP_NULL, IP_FLAG_FC_STACKCONTEXT);
        IPNET_ROUTESOCK(ipnet_routesock_addr_add(netif, IP_AF_INET, addr));
        IPNET_NETLINKSOCK(ipnet_rtnetlink_ip4_addr_add(netif, addr));
    }

 cleanup:
    if (ret < 0)
    {
        IPCOM_LOG3(NOTICE,
                   "IPv4: Failed to assign address %s to interface %s, code=%d",
                   ipcom_inet_ntop(IP_AF_INET, &addr->ipaddr_n, ipnet_ptr()->log_buf, sizeof(ipnet_ptr()->log_buf)),
                   netif->ipcom.name,
                   -ret);
        (void) ipnet_ip4_remove_addr(netif, addr->ipaddr_n);
        return ret;
    }

    return 0;
}


/*
 *===========================================================================
 *                       ipnet_ip4_get_ip_opt_next
 *===========================================================================
 * Description: Returns a pointer to the next IP-option
 * Parameters:  optprev - pointer to the IP-option that is in front of the
 *                        option the be returned or IP_NULL if the first
 *                        option should be returned.
 *              opts_ptr - pointer to the first IP-option
 *              optlen - total length of all IP-options
 * Returns:     Pointer to IP-option or IP_NULL if 'optprev' pointed to
 *              the last option.
 *
 */
IP_STATIC void *
ipnet_ip4_get_ip_opt_next(void *optprev, void *opts_ptr, int optlen)
{
    Ipnet_pkt_ip_opt *opt    = optprev;
    int               offset = opt ? (int)(((char *)opt + opt->len) - (char *)opts_ptr) : 0;

    while (offset < optlen)
    {
        opt = (Ipnet_pkt_ip_opt *) ((Ip_u8*) opts_ptr + offset);
        switch (opt->flag_class_num)
        {
        case IP_IPOPT_END:
            return IP_NULL;
        case IP_IPOPT_NOOP:
            offset++;
            break;
        default:
            if (opt->len >= 2 && opt->len <= optlen)
                return opt;
            return IP_NULL;
        }
    }

    return IP_NULL;
}


#ifdef IPNET_USE_RFC1256

/* Just stringify the state number/mode */
#define IPNET_RFC1256_MODE(m)       #m
#define IPNET_RFC1256_STATE(m,s)    #s



/*
 *===========================================================================
 *                    ipnet_ip4_rfc1256_sysvar_address
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_rfc1256_sysvar_address(Ipnet_netif        *netif,
                                 const char         *key,
                                 struct Ip_in_addr  *addr,
                                 Ip_u32             defaddr)
{
    char        addr_str[40];
    Ip_size_t   addr_str_len = sizeof(addr_str);
    char       *name = ipnet_ptr()->log_buf;

    /* coverity[secure_coding] */
    ipcom_strcpy(name, netif->ipcom.name);
    /* coverity[secure_coding] */
    ipcom_strcat(name, ".ipnet.rtdisc.");
    /* There's enough room in log_buf to contain these 3 strings */
    /* coverity[fixed_size_dest] */ 
    /* coverity[secure_coding] */
    ipcom_strcat(name, key);

    /* */
    if(ipcom_sysvar_get(name, addr_str, &addr_str_len) != IP_NULL)
    {
        if(ipcom_inet_pton(IP_AF_INET, addr_str, addr) == 1)
        {
            /* Sanity; must be default or 255.255.255.255 */
            if (addr->s_addr == defaddr || addr->s_addr == IP_INADDR_BROADCAST)
                return;
        }
    }

    /* Store default */
    addr->s_addr = defaddr;
}


/*
 *===========================================================================
 *                  ipnet_ip4_rfc1256_route_remove_auto
 *===========================================================================
 * Description: Callback used when all routes are to be removed from a specified
 *              interface.
 * Parameters:  [in] rt - The current route in the walk.
 *              [in] netif - The interface the route should be using to be removed.
 * Returns:     IP_TRUE - remove this route
 *              IP_FALSE - do not remove this route.
 *
 */
IP_STATIC Ip_bool
ipnet_ip4_rfc1256_route_remove_auto(Ipnet_route_entry *rt, Ipnet_netif *netif)
{
    Ipnet_route_entry *widen;
    Ipnet_route_entry *prev;

    /* Have to check the route with rt->narrow == IP_NULL and rt->prev == IP_NULL
       last since that route MUST be deleted by the caller ("rt" will be equal to
       the passed "rt" value in that case) */
    while (rt->narrow != IP_NULL)
        rt = rt->narrow;
    for (; rt != IP_NULL; rt = widen)
    {
        widen = rt->widen;

        while (rt->next != IP_NULL)
            rt = rt->next;
        for (; rt != IP_NULL; rt = prev)
        {
            prev = rt->prev;
            if (rt->netif == netif
                && IP_BIT_ISTRUE(rt->hdr.flags, IPNET_RTF_X_AUTO))
            {
                if (rt->narrow == IP_NULL && rt->widen == IP_NULL
                    && rt->next == IP_NULL && rt->prev == IP_NULL)
                    /*
                     * No entries using the same key, let the IPCOM
                     * code remove this route
                     */
                    return IP_TRUE;

                (void)ipnet_route_delete2(IPNET_ROUTE_GET_FAMILY(rt->head),
                                          IPNET_ROUTE_GET_VR(rt->head),
                                          IPNET_ROUTE_GET_TABLE(rt->head),
                                          rt->hdr.key,
                                          rt->hdr.mask,
                                          rt->gateway,
                                          netif->ipcom.ifindex,
                                          0,
                                          0,
                                          IP_FALSE);
            }
        }
    }
    return IP_FALSE;
}


/*
 *===========================================================================
 *                    ipnet_ip4_rfc1256_state_change
 *===========================================================================
 * Description: Change to a new state.
 * Parameters:  netif       - The network interface.
 *              state       - The state.
 * Returns:     IP_TRUE if the state is changed.
 *
 */
IP_STATIC Ip_bool
ipnet_ip4_rfc1256_state_change(Ipnet_netif *netif,
                               Ip_u8       state)
{
    /* */
    if (netif->inet4_rfc1256_state != state)
    {
        IPCOM_LOG4(DEBUG2,
                   "IPv4: %s %s RFC1256 changing state from %s to %s",
                   netif->ipcom.name,
                   IPNET_RFC1256_MODE(netif->inet4_rfc1256_mode),
                   IPNET_RFC1256_STATE(netif->inet4_rfc1256_mode, netif->inet4_rfc1256_state),
                   IPNET_RFC1256_STATE(netif->inet4_rfc1256_mode, state));

        ipnet_timeout_cancel(netif->inet4_rfc1256_tmo);
        netif->inet4_rfc1256_num    = 0;
        netif->inet4_rfc1256_state  = state;
        ipnet_ip4_rfc1256_state_run(netif);

        /* State has changed */
        return IP_TRUE;
    }

    /* Same state */
    return IP_FALSE;
}

/*
 *===========================================================================
 *                    ipnet_ip4_rfc1256_mode
 *===========================================================================
 * Description: Determine if a network interface is in HOST or ROUTER
 *              or NONE mode.
 * Parameters:  netif   - The network interface
 * Returns:     HOST, ROUTER or NONE
 *
 */
IP_STATIC Ip_u8
ipnet_ip4_rfc1256_mode(Ipnet_netif  *netif)
{
    Ip_bool ipnet_router;
    Ip_bool netif_router;

    /* Check the forwarding capabilities */
    ipnet_router = IP_BIT_ISTRUE(ipnet_shared()->flags, IPNET_FLAG_IPV4_FORWARD_PKT);
    netif_router = IP_BIT_ISFALSE(netif->flags2, IPNET_IFF2_NO_IPV4_FORWARD);

    if (IP_BIT_ISFALSE(netif->ipcom.flags, IP_IFF_UP))
    {
        /* Don't do anything if the interface is not UP */
        return IPNET_RFC1256_MODE_NONE;
    }

    /* Determine the RFC1256 state for this particular interface */
    if (ipnet_router && netif_router)
    {
        /*
         * We're configured as a router; see if router advertisements
         * are enabled
         */
#ifndef IPNET_RFC1256_ENABLE_ADVERTISEMENT
        if (ipnet_sysvar_netif_get_as_int_ex(IP_AF_INET,
                                             netif,
                                             "rtdisc.PerformRouterAdvertisement",
                                             IP_FALSE,
                                             ipnet_bool_map) != IP_FALSE)
#else
        if (ipnet_sysvar_netif_get_as_int_ex(IP_AF_INET,
                                             netif,
                                             "rtdisc.PerformRouterAdvertisement",
                                             IP_TRUE,
                                             ipnet_bool_map) != IP_FALSE)
#endif
        {
            /*
             * They're enabled, we need to flag us as a ROUTER
             * interface
             */
            return IPNET_RFC1256_MODE_ROUTER;
        }
    }
    else
    {
        /*
         * We're configured as a host; see if router solicitations are
         * enabled
         */
#ifndef IPNET_RFC1256_ENABLE_SOLICITATION
        if (ipnet_sysvar_netif_get_as_int_ex(IP_AF_INET,
                                             netif,
                                             "rtdisc.PerformRouterDiscovery",
                                             IP_FALSE,
                                             ipnet_bool_map) != IP_FALSE)
#else
        if (ipnet_sysvar_netif_get_as_int_ex(IP_AF_INET,
                                             netif,
                                             "rtdisc.PerformRouterDiscovery",
                                             IP_TRUE,
                                             ipnet_bool_map) != IP_FALSE)
#endif
        {
            /* They're enabled, we need to flag us as a HOST interface */
            return IPNET_RFC1256_MODE_HOST;
        }
    }

    /* We're in 'no mode' */
    return IPNET_RFC1256_MODE_NONE;
}


/*
 *===========================================================================
 *                    ipnet_ip4_rfc1256_advertise
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_rfc1256_advertise(Ipnet_netif *netif)
{
    Ipnet_ip4_addr_entry *addr;
    Ipnet_pkt_icmp       *icmp;
    Ip_u32                count;
    Ip_u32                max_count;
    Ip_u32                max;
    Ip_u32                min;
    Ip_u32                life;
    Ip_u32                next_tmo;
    Ipnet_icmp_param      param;
    Ipcom_pkt            *pkt;
    int                   ret;
    Ipnet_data           *net = ipnet_ptr();

    /* Get the basic values for timeouts */
    max = (Ip_u32) ipnet_sysvar_netif_get_as_int(IP_AF_INET,
                                                 netif,
                                                 "rtdisc.MaxAdvertisementInterval",
                                                 600);
    max = IP_MIN(1800, IP_MAX(4, max));
    min = (Ip_u32) ipnet_sysvar_netif_get_as_int(IP_AF_INET,
                                                 netif,
                                                 "rtdisc.MinAdvertisementInterval",
                                                 (int) (max * 3) / 4);
    min = IP_MIN(max, IP_MAX(min, 3));

    next_tmo =  ipcom_random();
    next_tmo %= ((max - min) * 1000);
    next_tmo += min * 1000;

    /* Next advertisement interval */
    if (netif->inet4_rfc1256_state == IPNET_RFC1256_ROUTER_STATE_BROADCASTING)
    {
        /* Send the advertisement */
        if (IP_BIT_ISFALSE(netif->inet4_rfc1256_flags, IPNET_RFC1256_FLAG_ROUTER_PENDING))
            ++netif->inet4_rfc1256_num;

        if (netif->inet4_rfc1256_num < IPNET_RFC1256_ROUTER_MAX_INITIAL_ADVERTISEMENTS)
            next_tmo = IP_MIN(next_tmo,IPNET_RFC1256_ROUTER_MAX_INITIAL_ADVERT_INTERVAL);
        else
        {
            /* Go advertising */
            (void)ipnet_ip4_rfc1256_state_change(netif, IPNET_RFC1256_ROUTER_STATE_ADVERTISING);
        }
    }

    /* No longer pending */
    IP_BIT_CLR(netif->inet4_rfc1256_flags, IPNET_RFC1256_FLAG_ROUTER_PENDING);

    pkt = IP_NULL;
    count = 0;      /* for warnings */
    max_count = 1;  /* for warnings */

    for (addr = netif->inet4_addr_list;  ; addr = addr->next)
    {
        char    addr_str[50];
        char    tmp_str[20];
        Ip_u32 *rt_addr_n;
        Ip_u32 *pref_lvl_n;

        if (pkt != IP_NULL && (count == max_count || addr == IP_NULL))
        {
            /* Done with all addresses, or all that will fit in this packet. */

            /* Grab the ICMP header */
            icmp = ipcom_pkt_push_front(pkt, IPNET_ICMP_HDR_SIZE);

            life = (Ip_u32) ipnet_sysvar_netif_get_as_int(IP_AF_INET,
                                                          netif,
                                                          "rtdisc.AdvertisementLifetime",
                                                          (int) (max * 3));
            life = IP_MAX(max, IP_MIN(9000, life));

            /* */
            icmp->data.advertise.num_addrs       = (Ip_u8) count;
            icmp->data.advertise.addr_entry_size = 2;
            icmp->data.advertise.lifetime        = ip_htons((Ip_u16) life);


            /* Clear the parameters */
            ipcom_memset(&param, 0, sizeof(param));

            /* Create IGMP message */
            if (IP_BIT_ISFALSE(netif->inet4_rfc1256_flags, IPNET_RFC1256_FLAG_ROUTER_MULTICAST))
                /* Use broadcast */
                param.to.s_addr = ip_htonl(IP_INADDR_BROADCAST);
            else
            {
                /* Use multicast */
                param.to.s_addr = ip_htonl(IP_INADDR_ALLHOSTS_GROUP);
                param.ttl       = 1;
            }

            param.vr        = netif->vr_index;
            param.ifindex   = netif->ipcom.ifindex;
            param.type      = IPNET_ICMP4_TYPE_ROUTER_ADVERT;
            param.recv_pkt  = pkt;

            pkt = IP_NULL;
            count = 0;
            max_count = 1;

            ret = ipnet_icmp4_send(&param, IP_FALSE);
            if (ret < 0)
            {
                if (param.recv_pkt != IP_NULL)
                    /* ipnet_icmp4_send() did not free the orginal packet */
                    ipcom_pkt_free(param.recv_pkt);
                break; /* Don't try to send any more ... */
            }
        }

        if (addr == IP_NULL)
            break;  /* all done */

        if (addr->type != IPNET_ADDR_TYPE_UNICAST)
            continue;

        /* Router address */
        /* coverity[secure_coding] */
        ipcom_strcpy(addr_str, "rtdisc.");
        ipcom_inet_ntop(IP_AF_INET, &addr->ipaddr_n, tmp_str, sizeof(tmp_str));
        /* coverity[secure_coding] */
        ipcom_strcat(addr_str, tmp_str);
        /* coverity[secure_coding] */
        ipcom_strcat(addr_str, ".Advertise");

        /* Is it enabled? */
        if (ipnet_sysvar_netif_get_as_int(IP_AF_INET,
                                          netif,
                                          addr_str,
                                          IP_TRUE) == IP_FALSE)
            continue;

        if (pkt == IP_NULL)
        {
            int space;

            /* Create a reply packet. */
            pkt = ipcom_pkt_malloc(ipnet_conf_ip4_min_mtu,
                                   IP_FLAG_FC_STACKCONTEXT);
            if (pkt == IP_NULL)
            {
                IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_CRITICAL,
                                  1, 1, IPCOM_WV_NETDEVENT_CRITICAL, IPCOM_WV_NETD_SEND,
                                  ipnet_ip4_rfc1256_advertise, IPCOM_WV_NETD_NOBUFS,
                                  IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
                IPNET_STATS(net, icmp4_send_nomem++);
                IPCOM_MIB2(net, icmpOutErrors++);
                IPCOM_MIB2_SYSWI_U32_ADD(net, v4, icmpStatsOutErrors, 1);
                break;
            }

            ipnet_pkt_set_stack_instance(pkt, net);
            ipcom_pkt_reserve_data(pkt, 0);
            IP_BIT_SET(pkt->flags, IPCOM_PKT_FLAG_NONBLOCKING);

            /* Need space for at least one Router Address / Preference Level pair. */

            space = ipcom_conf_max_link_hdr_size + IPNET_IP_HDR_SIZE + IPNET_ICMP_HDR_SIZE;
            ip_assert(pkt->start >= space + 8);

            max_count = (Ip_u32)(pkt->start - space) / 8;
            count = 0;
        }

        /* Preference */
        /* coverity[secure_coding] */
        ipcom_strcpy(addr_str, "rtdisc.");
        ipcom_inet_ntop(IP_AF_INET, &addr->ipaddr_n, tmp_str, sizeof(tmp_str));
        /* coverity[secure_coding] */
        ipcom_strcat(addr_str, tmp_str);
        /* coverity[secure_coding] */
        ipcom_strcat(addr_str, ".PreferenceLevel");

        pref_lvl_n = ipcom_pkt_push_front(pkt, sizeof(*pref_lvl_n));
        *pref_lvl_n = ip_htonl(ipnet_sysvar_netif_get_as_int(IP_AF_INET,
                                                             netif,
                                                             addr_str,
                                                             0));

        rt_addr_n = ipcom_pkt_push_front(pkt, sizeof(*rt_addr_n));
        *rt_addr_n = addr->ipaddr_n;

        count++;
    }

    ip_assert(pkt == IP_NULL);

    ipnet_ip4_rfc1256_advertise_schedule(netif, next_tmo);
}


/*
 *===========================================================================
 *                    ipnet_ip4_rfc1256_advertise_schedule
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_rfc1256_advertise_schedule(Ipnet_netif    *netif,
                                     Ip_u32         tmo)
{
    /* Verify that we're in a state where its allowed */
    if (netif->inet4_rfc1256_mode == IPNET_RFC1256_MODE_ROUTER)
    {
        switch (netif->inet4_rfc1256_state)
        {
        case IPNET_RFC1256_ROUTER_STATE_BROADCASTING:
        case IPNET_RFC1256_ROUTER_STATE_ADVERTISING:
            ipnet_timeout_cancel(netif->inet4_rfc1256_tmo);
            (void)ipnet_timeout_schedule(ipnet_ptr(),
                                         tmo,
                                         (Ipnet_timeout_handler) ipnet_ip4_rfc1256_advertise,
                                         netif,
                                         &netif->inet4_rfc1256_tmo);
            break;
        default:
            /* No; clear the advert bit */
            IP_BIT_CLR(netif->inet4_rfc1256_flags, IPNET_RFC1256_FLAG_ROUTER_PENDING);
            break;
        }
    }
}


#ifdef IPNET_DEBUG
/*
 *===========================================================================
 *                    ipnet_ip4_rfc1256_advertise_tmo_to_string
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC int
ipnet_ip4_rfc1256_advertise_tmo_to_string(Ipnet_netif *netif, char *buf, Ip_size_t buf_len)
{
    return ipcom_snprintf(buf,
                          buf_len,
                          "ICMP Router Discovery Message on %s",
                          netif->ipcom.name);
}


/*
 *===========================================================================
 *                    ipnet_ip4_rfc1256_solicit_tmo_to_string
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC int
ipnet_ip4_rfc1256_solicit_tmo_to_string(Ipnet_netif *netif, char *buf, Ip_size_t buf_len)
{
    return ipcom_snprintf(buf,
                          buf_len,
                          "ICMP Router Solicitation Message on %s",
                          netif->ipcom.name);
}
#endif /* IPNET_DEBUG */


/*
 *===========================================================================
 *                    ipnet_ip4_rfc1256_solicit
 *===========================================================================
 * Description: Start the solicitation.
 * Parameters:
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_rfc1256_solicit(Ipnet_netif *netif)
{
    Ipnet_icmp_param    param;

    /* Clear the parameters */
    ipcom_memset(&param, 0, sizeof(param));

    /* Create IGMP message */
    if (IP_BIT_ISFALSE(netif->inet4_rfc1256_flags, IPNET_RFC1256_FLAG_ROUTER_MULTICAST))
        /* Use broadcast */
        param.to.s_addr = ip_htonl(IP_INADDR_BROADCAST);
    else
    {
        /* Use multicast */
        param.to.s_addr = ip_htonl(IP_INADDR_ALLHOSTS_GROUP);
        param.ttl       = 1;
    }

    param.vr        = netif->vr_index;
    param.ifindex   = netif->ipcom.ifindex;
    param.type      = IPNET_ICMP4_TYPE_ROUTER_SOLICIT;
    (void)ipnet_icmp4_send(&param, IP_FALSE);

    /* SEND THE SOLICITATION */
    IPCOM_LOG2(DEBUG2,
               "IPv4: %s %s RFC1256 sending solicitation",
               netif->ipcom.name,
               IPNET_RFC1256_MODE(netif->inet4_rfc1256_mode));

    /* Should I schedule a new solicitation */
    if (++netif->inet4_rfc1256_num < IPNET_RFC1256_HOST_MAX_SOLICITATIONS)
    {
        if (ipnet_timeout_schedule(ipnet_pri_ptr(),
                                   IPNET_RFC1256_HOST_SOLICITATION_INTERVAL,
                                   (Ipnet_timeout_handler) ipnet_ip4_rfc1256_solicit,
                                   netif,
                                   &netif->inet4_rfc1256_tmo) == 0)
            return;
    }

    /* Go IDLE */
    (void)ipnet_ip4_rfc1256_state_change(netif, IPNET_RFC1256_HOST_STATE_IDLE);
}


/*
 *===========================================================================
 *                    ipnet_ip4_rfc1256_state_run
 *===========================================================================
 * Description: Run the currently set state.
 * Parameters:  netif - The network interface.
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_rfc1256_state_run(Ipnet_netif *netif)
{
    Ip_u32 tmp;

    /*
     * This state machine must be run by the primary instance.
     */
    ip_assert(ipnet_primary_instance_idx() == ipnet_this());

    /* If we're running and up, do start the rfc1256 processing */
    if (IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_RUNNING|IP_IFF_UP) == (IP_IFF_RUNNING|IP_IFF_UP))
    {
        /* Did we retrieve a state? */
        switch (netif->inet4_rfc1256_mode)
        {
        case IPNET_RFC1256_MODE_NONE:
            break;

        case IPNET_RFC1256_MODE_HOST:
            switch (netif->inet4_rfc1256_state)
            {
            case IPNET_RFC1256_GENERIC_STATE_NONE:
                break;
            case IPNET_RFC1256_GENERIC_STATE_SHUTDOWN:
            {
                Ipcom_route *rtab;

                /* Try lookup the default route table for this netif */
                ipnet_route_lock();
                if (ipnet_route_get_rtab_l(IP_AF_INET, netif->vr_index, IPCOM_ROUTE_TABLE_DEFAULT, &rtab) == 0)
                {
                    ipcom_route_walk_tree(rtab,
                                          (Ipcom_route_walk_cb) ipnet_ip4_rfc1256_route_remove_auto,
                                          netif);
                }
                ipnet_route_unlock();
            }
            /* Go to the 'no' state */
            (void)ipnet_ip4_rfc1256_state_change(netif, IPNET_RFC1256_GENERIC_STATE_NONE);
            break;
            case IPNET_RFC1256_GENERIC_STATE_INITIALIZING:
                /* Go solicit */
                (void)ipnet_ip4_rfc1256_state_change(netif, IPNET_RFC1256_HOST_STATE_SOLICIT);

                /* Calculate an initial delay */
                tmp = ipcom_random();
                tmp %= IPNET_RFC1256_HOST_MAX_SOLICITATION_DELAY;

                /* Move to SETUP */
                if (tmp == 0
                    || ipnet_timeout_schedule(ipnet_pri_ptr(),
                                              tmp,
                                              (Ipnet_timeout_handler) ipnet_ip4_rfc1256_solicit,
                                              netif,
                                              &netif->inet4_rfc1256_tmo) != 0)
                {
                    /* No delay or failed to schedule timeout */
                    ipnet_ip4_rfc1256_solicit(netif);
                }
                break;
            case IPNET_RFC1256_HOST_STATE_SOLICIT:
                /* We're soliciting */
                break;
            case IPNET_RFC1256_HOST_STATE_IDLE:
                break;
            }
            break;
        case IPNET_RFC1256_MODE_ROUTER:
            switch (netif->inet4_rfc1256_state)
            {
            case IPNET_RFC1256_GENERIC_STATE_NONE:
                break;
            case IPNET_RFC1256_GENERIC_STATE_SHUTDOWN:
                /* Go to the 'no' state */
                (void)ipnet_ip4_rfc1256_state_change(netif, IPNET_RFC1256_GENERIC_STATE_NONE);
                break;
            case IPNET_RFC1256_GENERIC_STATE_INITIALIZING:
                /* Go to the 'no' state */
                (void)ipnet_ip4_rfc1256_state_change(netif, IPNET_RFC1256_ROUTER_STATE_BROADCASTING);

                /* Calculate an initial delay */
                tmp =  ipcom_random();
                tmp %= IPNET_RFC1256_ROUTER_MAX_RESPONSE_DELAY;

                /* Schedule an advertisement */
                ipnet_ip4_rfc1256_advertise_schedule(netif, tmp);
                break;
            case IPNET_RFC1256_ROUTER_STATE_BROADCASTING:
                break;
            case IPNET_RFC1256_ROUTER_STATE_ADVERTISING:
                break;
            }
            break;
        }
    }
}


/*
 *===========================================================================
 *                    ipnet_ip4_rfc1256_solicit_input
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_rfc1256_solicit_input(Ipnet_dst_cache         *dst,
                                Ipnet_netif             *netif,
                                Ipnet_pkt_icmp          *icmp_hdr,
                                int                     icmp_len)
{
    /* Is this interface a router? */
    if (netif->inet4_rfc1256_mode == IPNET_RFC1256_MODE_ROUTER)
    {
        Ipnet_ip4_addr_entry *addr;

        if (icmp_len < 8)
        {
            IPCOM_LOG2(DEBUG2,
                       "IPv4: %s %s RFC1256 received solicitation too short --> discarding",
                       netif->ipcom.name,
                       IPNET_RFC1256_MODE(netif->inet4_rfc1256_mode));
            return;
        }

        if (icmp_hdr->code != 0)
        {
            IPCOM_LOG3(DEBUG2,
                       "IPv4: %s %s RFC1256 received solicitation has code %u, should be 0 --> discarding",
                       netif->ipcom.name,
                       IPNET_RFC1256_MODE(netif->inet4_rfc1256_mode),
                       icmp_hdr->code);
            return;
        }

        /*
         * We've got an address; check the interface in order to
         * verify that we've got a correct submask/net location
         */
        /* Verify whether we should be advertising this address */
        for (addr = netif->inet4_addr_list; addr != IP_NULL; addr = addr->next)
        {
            if (addr->type == IPNET_ADDR_TYPE_UNICAST)
            {
                /* These two seems to be on the same subnet */
                if ((addr->ipaddr_n & addr->netmask_n) == (dst->flow_spec.from.in.s_addr & addr->netmask_n))
                    break;
            }
        }

            /* No go */
        if (addr == IP_NULL)
        {
            IPCOM_LOG3(DEBUG2,
                       "IPv4: %s %s RFC1256 received solicitation from invalid source address %s --> discarding",
                       netif->ipcom.name,
                       IPNET_RFC1256_MODE(netif->inet4_rfc1256_mode),
                       ipcom_inet_ntop(IP_AF_INET,
                                       &dst->flow_spec.from.in.s_addr,
                                       ipnet_ptr()->log_buf,
                                       sizeof(ipnet_ptr()->log_buf)));
            return;
        }

        /* Do we have any advertisements already pending? */
        if (IP_BIT_ISFALSE(netif->inet4_rfc1256_flags, IPNET_RFC1256_FLAG_ROUTER_PENDING))
        {
            Ip_u32  next_tmo;

            /* No; set the bit and schedule an advertisement */
            IP_BIT_SET(netif->inet4_rfc1256_flags, IPNET_RFC1256_FLAG_ROUTER_PENDING);

            /* Randomize the timeout */
            next_tmo = ipcom_random();
            next_tmo %= IPNET_RFC1256_ROUTER_MAX_RESPONSE_DELAY;

            /* Make certain that its atleast 1 */
            next_tmo = IP_MAX(1, next_tmo);

            IPCOM_LOG2(DEBUG2,
                       "IPv4: %s %s RFC1256 receiving solicitation, scheduling advertisement",
                       netif->ipcom.name,
                       IPNET_RFC1256_MODE(netif->inet4_rfc1256_mode));

            /* Do schedule the advertisement */
            ipnet_ip4_rfc1256_advertise_schedule(netif, next_tmo);
        }
        else
        {
            IPCOM_LOG2(DEBUG2,
                       "IPv4: %s %s RFC1256 receiving redundant solicitation, advertisement already scheduled",
                       netif->ipcom.name,
                       IPNET_RFC1256_MODE(netif->inet4_rfc1256_mode));
        }
    }
}


/*
 *===========================================================================
 *                   ipnet_ip4_rfc1256_advertise_input
 *===========================================================================
 * Description:
 * Parameters:  netif -
 *              icmp_hdr -
 *              icmp_len -
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_rfc1256_advertise_input(Ipnet_netif             *netif,
                                  Ipnet_pkt_icmp          *icmp_hdr,
                                  int                     icmp_len)
{
    /* Is this interface a host (that accepts advertisements)? */
    if (netif->inet4_rfc1256_mode == IPNET_RFC1256_MODE_HOST)
    {
        Ip_u32 rtaddr;
        Ip_u16 lifetime;
        Ip_u32 rtpref;
        Ip_u32 tmp;
        Ip_u8  *data;

        if (icmp_hdr->code != 0)
        {
            IPCOM_LOG3(DEBUG2,
                       "IPv4: %s %s RFC1256 received advertisement has code %u, should be 0 --> discarding",
                       netif->ipcom.name,
                       IPNET_RFC1256_MODE(netif->inet4_rfc1256_mode),
                       icmp_hdr->code);
            return;
        }

        if (icmp_len < 8)
        {
            IPCOM_LOG2(DEBUG2,
                       "IPv4: %s %s RFC1256 received advertisement too short --> discarding",
                       netif->ipcom.name,
                       IPNET_RFC1256_MODE(netif->inet4_rfc1256_mode));
            return;
        }

        if (icmp_hdr->data.advertise.num_addrs == 0)
        {
            IPCOM_LOG2(DEBUG2,
                       "IPv4: %s %s RFC1256 received advertisement contains no addresses --> discarding",
                       netif->ipcom.name,
                       IPNET_RFC1256_MODE(netif->inet4_rfc1256_mode));
            return;
        }

        if (icmp_hdr->data.advertise.addr_entry_size < 2)
        {
            IPCOM_LOG2(DEBUG2,
                       "IPv4: %s %s RFC1256 received advertisement has too small entry size --> discarding",
                       netif->ipcom.name,
                       IPNET_RFC1256_MODE(netif->inet4_rfc1256_mode));
            return;
        }

        /* Verify that it indeed holds all the advertised information */
        tmp = (Ip_u32)icmp_hdr->data.advertise.num_addrs * (Ip_u32)icmp_hdr->data.advertise.addr_entry_size * 4;
        if (icmp_len < (int) tmp)
        {
            IPCOM_LOG4(DEBUG2,
                       "IPv4: %s %s RFC1256 received advertisement too short (%u, should be %u)--> discarding",
                       netif->ipcom.name,
                       IPNET_RFC1256_MODE(netif->inet4_rfc1256_mode),
                       icmp_len,
                       tmp);
            return;
        }

        /* Get the lifetime */
        lifetime = IP_GET_NTOHS(&icmp_hdr->data.advertise.lifetime);

        /* Go through the addresses; */
        data = (Ip_u8 *)&icmp_hdr->data.advertise.advert[0];
        while (icmp_hdr->data.advertise.num_addrs--)
        {
            Ipnet_ip4_addr_entry    *addr;

            /* Grab the address and preference levels */
            rtaddr = IP_GET_32ON8(data);
            rtpref = IPNET_RFC1256_SIGNED_TO_HOPCOUNT(IP_GET_NTOHL((data + 4)));

            /* Advance past this entry */
            data += icmp_hdr->data.advertise.addr_entry_size * 4;

            /* Determine what to do */
            if (rtpref == 0xffffffff)
            {
                IPCOM_LOG3(DEBUG2,
                           "IPv4: %s %s RFC1256 advertised address %s tagged as non-default --> skipping",
                           netif->ipcom.name,
                           IPNET_RFC1256_MODE(netif->inet4_rfc1256_mode),
                           ipcom_inet_ntop(IP_AF_INET, &rtaddr, ipnet_ptr()->log_buf, sizeof(ipnet_ptr()->log_buf)));
                continue;
            }

            /*
             * We've got an address; check the interface in order to
             * verify that we've got a correct submask/net location
             */
            for (addr = netif->inet4_addr_list; addr != IP_NULL; addr = addr->next)
            {
                if (addr->type == IPNET_ADDR_TYPE_UNICAST)
                {
                    /* These two seems to be on the same subnet */
                    if ((addr->ipaddr_n & addr->netmask_n) == (rtaddr & addr->netmask_n))
                        break;
                }
            }

            /* Found an address? */
            if (addr == IP_NULL)
            {
                IPCOM_LOG3(DEBUG2,
                           "IPv4: %s %s RFC1256 advertised address %s not valid on interface --> trying next",
                           netif->ipcom.name,
                           IPNET_RFC1256_MODE(netif->inet4_rfc1256_mode),
                           ipcom_inet_ntop(IP_AF_INET,
                                           &rtaddr,
                                           ipnet_ptr()->log_buf,
                                           sizeof(ipnet_ptr()->log_buf)));
                continue;
            }
            else
            {
                /* We've got one; do add this default gateway with the appropriate timeout (first verify if it exists) */
                int                     ret;
                Ipnet_route_entry       *rt;
                struct Ip_sockaddr_in   gw;

                ipcom_memset(&gw, 0, sizeof(gw));
                gw.sin_family       = IP_AF_INET;
                IPCOM_SA_LEN_SET(&gw, sizeof(gw));
                gw.sin_addr.s_addr  = rtaddr;
                ipnet_route_lock();
                ret = ipnet_route_raw_lookup2_l(IP_AF_INET,
                                                netif->vr_index,
                                                IPCOM_ROUTE_TABLE_DEFAULT,
                                                0,
                                                &ip_inaddr_any,
                                                0,
                                                IP_NULL,
                                                (struct Ip_sockaddr *) &gw,
                                                netif->ipcom.ifindex,
                                                &rt);

                if (ret == IPNET_ROUTE_PERFECT_MATCH)
                {
                    /* Already existed; update parameters */
                    if (IP_BIT_ISFALSE(rt->hdr.flags, IPNET_RTF_X_AUTO))
                    {
                        /*
                         * Added by something else; statically or by some
                         * other means of configuration; do not modify
                         */
                        ipnet_route_unlock();
                        continue;
                    }

                    if (lifetime == 0)
                    {
                        /* Delete this particular route */
                        (void)ipnet_route_delete2(IP_AF_INET,
                                                  netif->vr_index,
                                                  IPNET_ROUTE_GET_TABLE(rt->head),
                                                  rt->hdr.key,
                                                  rt->hdr.mask,
                                                  rt->gateway,
                                                  rt->netif->ipcom.ifindex,
                                                  0,
                                                  0,
                                                  IP_FALSE);
                    }
                    else
                    {
                        if (rt->metrics.rmx_hopcount != rtpref)
                        {
                            /* Update the metrics */
                            rt->metrics.rmx_hopcount = rtpref;
                            ipnet_route_has_changed_l(rt);
                        }

                        /* Update the lifetime of the route */
                        ipnet_route_set_lifetime_l(rt, lifetime);
                    }
                }
                else if (lifetime != 0)
                {
                    struct Ipnet_route_add_param param;
                    struct Ipnet_rt_metrics      metrics;

                    /* Only add it if we've gotten a lifetime; otherwise
                     * its a delete request */
                    ipcom_memset(&metrics, 0, sizeof(metrics));
                    metrics.rmx_expire   = lifetime;
                    metrics.rmx_hopcount = rtpref;

                    /* Add the route */
                    ipcom_memset(&param, 0, sizeof(param));
                    param.domain     = IP_AF_INET;
                    param.vr         = netif->vr_index;
                    param.table      = IPCOM_ROUTE_TABLE_DEFAULT;
                    param.netif      = netif;
                    param.flags      = IPNET_RTF_UP | IPNET_RTF_DONE | IPNET_RTF_GATEWAY | IPNET_RTF_X_AUTO;
                    param.key        = &ip_inaddr_any;
                    param.netmask    = &ip_inaddr_any;
                    param.gateway    = (struct Ip_sockaddr *) &gw;
                    param.metrics    = &metrics;

                    (void) ipnet_route_add(&param);
                }
                ipnet_route_unlock();
            }
        }
    }
}


/*
 *===========================================================================
 *                    ipnet_ip4_rfc1256_mode_update
 *===========================================================================
 * Description: Initialize the RFC1256 portion of the interface
 * Parameters:  vr      - The virtual router
 *              netif   - The network interface
 * Returns:     IP_TRUE if mode's been changed.
 *
 */
IP_GLOBAL Ip_bool
ipnet_ip4_rfc1256_mode_update(Ip_u16        vr,
                              Ipnet_netif   *netif)
{
    int mode;

    if (netif == IP_NULL)
    {
        unsigned    i;

        /* Need to do a global update; some major flag has changed */
        /* coverity[result_independent_of_operands] */
        IPNET_NETIF_FOR_EACH_ON_VR(netif, vr, i)
        {
            /* Go through them all and update the mode */
            (void)ipnet_ip4_rfc1256_mode_update(vr, netif);
        }

        return IP_TRUE;
    }


    mode = ipnet_ip4_rfc1256_mode(netif);

    /* New mode? */
    if (mode != netif->inet4_rfc1256_mode)
    {
        struct Ip_in_addr addr;

        IPCOM_LOG3(DEBUG2,
                   "IPv4: %s RFC1256 changing mode from %s to %s",
                   netif->ipcom.name,
                   IPNET_RFC1256_MODE(netif->inet4_rfc1256_mode),
                   IPNET_RFC1256_MODE(mode));

        /* Cleanup the current mode */
        (void)ipnet_ip4_rfc1256_state_change(netif, IPNET_RFC1256_GENERIC_STATE_SHUTDOWN);

        /* We're changing mode; have we registered ourselves to the ROUTER multicast? */
        if (mode == IPNET_RFC1256_MODE_ROUTER)
        {
            /* Remove it */
            ipnet_ip4_remove_addr(netif, ip_htonl(IP_INADDR_ALLRTRS_GROUP));
        }

        /* Switch to the selected mode */
        netif->inet4_rfc1256_mode   = (Ip_u8)mode;
        netif->inet4_rfc1256_flags  = 0;

        /**/
        if (mode == IPNET_RFC1256_MODE_ROUTER)
        {
            /* Retrieve the configured address */
            ipnet_ip4_rfc1256_sysvar_address(netif,
                                             "AdvertisementAddress",
                                             &addr,
                                             ip_htonl(IP_INADDR_ALLHOSTS_GROUP));

            /* Check the configuration; do we use multicast or broadcast? */
            if (addr.s_addr == ip_htonl(IP_INADDR_ALLHOSTS_GROUP))
            {
                /* Remember that we're interested in using multicast advertisements */
                IP_BIT_SET(netif->inet4_rfc1256_flags, IPNET_RFC1256_FLAG_ROUTER_MULTICAST);
            }

            /* Add the multicast address */
            ipnet_ip4_add_addr2(netif,
                                ip_htonl(IP_INADDR_ALLRTRS_GROUP),
                                IP_IN_CLASSD_NET,
                                IPNET_IP4_ADDR_FLAG_AUTOMATIC,
                                IPNET_ADDR_TYPE_MULTICAST);

        }
        else if (mode == IPNET_RFC1256_MODE_HOST)
        {
            /* Retrieve the configured address */
            ipnet_ip4_rfc1256_sysvar_address(netif,
                                             "SolicitationAddress",
                                             &addr,
                                             ip_htonl(IP_INADDR_ALLRTRS_GROUP));
            /* Check the configuration; do we use multicast or broadcast? */
            if (addr.s_addr == ip_htonl(IP_INADDR_ALLRTRS_GROUP))
            {
                /* Remember that we're interested in multicast solicitations */
                IP_BIT_SET(netif->inet4_rfc1256_flags, IPNET_RFC1256_FLAG_HOST_MULTICAST);
            }
        }


        netif->inet4_rfc1256_state  = IPNET_RFC1256_GENERIC_STATE_INITIALIZING;
        netif->inet4_rfc1256_num    = 0;

        /* Reset the state */
        ipnet_ip4_rfc1256_state_run(netif);

        /* We've changed state */
        return IP_TRUE;
    }

    /* No mode change */
    return IP_FALSE;
}

#endif /* IPNET_USE_RFC1256 */


#ifdef IPNET_USE_RFC3927
/*
 *===========================================================================
 *                    ipnet_ip4_lladdr_generate
 *===========================================================================
 * Description: Generate a link local IPv4 address
 * Parameters:  addr - Pointer where the address should be stored
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_lladdr_generate(Ipnet_netif *netif)
{
    if (ipnet_sysvar_netif_get_as_int_ex(IP_AF_INET, netif, "linklocal.TEST", 0, ipnet_bool_map) == 0)
    {
        Ip_u32 range;
        Ip_u32 base;

        /* Genererate an address in the range 169.254.1.0 - 169.254.254.255 */
        (void) ipcom_inet_pton(IP_AF_INET, "169.254.1.0", &base);
        base = ip_ntohl(base);
        (void) ipcom_inet_pton(IP_AF_INET, "169.254.254.255", &range);
        range = ip_ntohl(range) - base + 1;
        netif->inet4_lladdr.s_addr = ip_htonl((Ip_u32)ipcom_rand() % range  + base);
    }
    else
    {
        static char *addrs[] = {
            "169.254.1.0",
            "169.254.1.1",
        };

        /* Testing, use a specific address */
        (void) ipcom_inet_pton(IP_AF_INET,
                               addrs[netif->acd.conflicts % 2],
                               &netif->inet4_lladdr.s_addr);
    }
}
#endif /* IPNET_USE_RFC3927 */

#if defined(IPNET_USE_RFC5227) || defined(IPNET_USE_RFC3927)
/*
 *===========================================================================
 *                     ipnet_ip4_acd_defend
 *===========================================================================
 * Description: Timeout for the DEFEND state.
 * Parameters:  addr - The defended address.
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_acd_defend(Ipnet_ip4_addr_entry *addr)
{
    /* The address was successfully defended */
    ipnet_ip4_acd_set_state(addr, IPNET_IP4_ACD_STATE_ACTIVE);
}


/*
 *===========================================================================
 *                    ipnet_ip4_acd_announce
 *===========================================================================
 * Description: Timeout handler for the ANNOUNCE state.
 * Parameters:  addr - The address that should be announced.
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_acd_announce(Ipnet_ip4_addr_entry *addr)
{
    Ipnet_netif *netif = addr->netif;

    if (addr->acd.num-- == 0)
        ipnet_ip4_acd_set_state(addr, IPNET_IP4_ACD_STATE_ACTIVE);
    else
    {
        ipnet_timeout_cancel(addr->acd.tmo);
        if (ipnet_timeout_schedule(ipnet_pri_ptr(),
                                   1000 * (Ip_u32) netif->conf.inet.ll_announce_interval,
                                   (Ipnet_timeout_handler) ipnet_ip4_acd_announce,
                                   addr,
                                   &addr->acd.tmo))
            ipnet_ip4_acd_set_state(addr, IPNET_IP4_ACD_STATE_DISABLED);
        else
            /* Send ARP gratuitous probes */
            ipnet_arp_request(netif,
                              0,
                              addr->ipaddr_n,
                              IP_TRUE,
                              IP_NULL,
                              IP_NULL);
    }
}


/*
 *===========================================================================
 *                    ipnet_ip4_acd_probe
 *===========================================================================
 * Description: Timeout handler for the PROBE state
 * Parameters:  addr - The IPv4 address to probe for duplicates.
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_acd_probe(Ipnet_ip4_addr_entry *addr)
{
    Ipnet_netif *netif = addr->netif;

    if (addr->acd.num-- == 0)
        ipnet_ip4_acd_set_state(addr, IPNET_IP4_ACD_STATE_ANNOUNCE);
    else
    {
        Ip_u32 base;
        Ip_u32 range;

        base = (Ip_u32)netif->conf.inet.ll_probe_min * 1000;
        range = (Ip_u32)netif->conf.inet.ll_probe_max * 1000;
        range = (range <= base ? 1 : range - base);

        ipnet_timeout_cancel(addr->acd.tmo);
        if (ipnet_timeout_schedule(ipnet_pri_ptr(),
                                   (Ip_u32)ipcom_rand() % range + base,
                                   (Ipnet_timeout_handler) ipnet_ip4_acd_probe,
                                   addr,
                                   &addr->acd.tmo))
            ipnet_ip4_acd_set_state(addr, IPNET_IP4_ACD_STATE_DISABLED);
        else
            /* Send ARP probes */
            ipnet_arp_request(netif,
                              0,
                              addr->ipaddr_n,
                              -1,
                              IP_NULL,
                              IP_NULL);
    }
}


/*
 *===========================================================================
 *                     ipnet_ip4_acd_init_wait
 *===========================================================================
 * Description: Timeout handler for the init wait timer.
 *              Used when rate limit is enforced.
 * Parameters:  addr - The address probed for address conflicts.
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_acd_init_wait(Ipnet_ip4_addr_entry *addr)
{
    ipnet_ip4_acd_set_state(addr, IPNET_IP4_ACD_STATE_INIT);
}


/*
 *===========================================================================
 *                     ipnet_ip4_acd_probe_wait
 *===========================================================================
 * Description: Timeout handler for the probe wait timer.
 * Parameters:  addr - The address probed for address conflicts.
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_acd_probe_wait(Ipnet_ip4_addr_entry *addr)
{
    ipnet_ip4_acd_set_state(addr, IPNET_IP4_ACD_STATE_PROBE);
}
#endif /* #if defined(IPNET_USE_RFC5227) || defined(IPNET_USE_RFC3927)  */

#ifdef IPNET_USE_RFC3927
/*
 *===========================================================================
 *                     ipnet_ip4_lladdr_add
 *===========================================================================
 * Description: Adds a link local address on the interface.
 * Parameters:  netif - The interface to configure for IPv4 link local address.
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_lladdr_add(Ipnet_netif *netif)
{
    Ipnet_ip4_addr_entry *ip4_addr;

    ipnet_ip4_lladdr_init(netif);
    if(netif->inet4_lladdr.s_addr != IP_INADDR_ANY)
    {
        /* Ok. we should assign a link local address to this interface */
        (void) ipnet_ip4_add_addr2(netif,
                                   netif->inet4_lladdr.s_addr,
                                   ip_htonl(0xffff0000),
                                   IPNET_IP4_ADDR_FLAG_AUTOMATIC |
                                   IPNET_IP4_ADDR_FLAG_LINK_LOCAL |
                                   IPNET_IP4_ADDR_FLAG_TENTATIVE,
                                   IPNET_ADDR_TYPE_UNICAST);
        ip4_addr = ipnet_ip4_get_addr_entry(netif->inet4_lladdr.s_addr, netif->vr_index, netif);
        if(ip4_addr == IP_NULL)
        {
            /* Failed to add the address for some reason. */
            IPCOM_LOG1(ERR,"Could not add link local address to interface %s", &netif->ipcom.name);
        }
        else
            ipnet_ip4_acd_set_state(ip4_addr, IPNET_IP4_ACD_STATE_INIT);
    }
}

/*
 *===========================================================================
 *                     ipnet_ip4_lladdr_isenabled
 *===========================================================================
 * Description: Checks if link local address use is enabled on the interface.
 * Parameters:  netif - The interface to configure for IPv4 link local address.
 * Returns:     IP_TRUE if enabled, IP_FALSE if disabled
 *
 */
IP_STATIC Ip_bool
ipnet_ip4_lladdr_isenabled(Ipnet_netif *netif)
{
    Ip_bool     enabled = IP_FALSE;
    char       *iflist;
    char       *ifname;
    char       *saveptr;

    /*
     * Using ipnet.inet.AutoConf is the preferred way, but VxWorks
     * still uses the ipnet.inet.linklocal.interfaces variable since
     * it fit much better into the CDF machinery
     */
    if (ipnet_this() == ipnet_primary_instance_idx())
    {
        enabled = netif->conf.inet.auto_conf;
        if (!enabled && ipnet_shared()->conf.inet.ll_if_list != IP_NULL)
        {
            iflist = ipcom_strdup(ipnet_shared()->conf.inet.ll_if_list);
            if (iflist != IP_NULL)
            {
                for (ifname = ipcom_strtok_r(iflist, " ,", &saveptr);
                     ifname != IP_NULL;
                     ifname = ipcom_strtok_r(IP_NULL, " ,", &saveptr))
                    if (ipcom_strcmp(ifname, netif->ipcom.name) == 0)
                    {
                        enabled = IP_TRUE;
                        break;
                    }
                ipcom_free(iflist);
            }
        }
    }
    /*
     * else: only one stack instance must run this state machine all
     * other instances will just mirror what instance 0 when it comes
     * to automatic address resolution.
     */
    return enabled;
}

/*
 *===========================================================================
 *                     ipnet_ip4_lladdr_init
 *===========================================================================
 * Description: Initializes usage of link local address on the interface.
 * Parameters:  netif - The interface to configure for IPv4 link local address.
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_lladdr_init(Ipnet_netif *netif)
{
    Ip_bool enabled;

    enabled = ipnet_ip4_lladdr_isenabled(netif);

    if (enabled)
    {
        if (IP_BIT_ISFALSE(netif->flags2, IPNET_IFF2_RANDOM_SEED))
        {
            /*
             * init the seed with a random number so that other
             * interfaces seed also has an effect
             */
            unsigned seed = ipcom_random();
            unsigned i;

            for (i = 0; i < netif->ipcom.link_addr_size; i++)
                seed += (unsigned) (netif->ipcom.link_addr[i] << (8u * (i & 3u)));
            IP_BIT_SET(netif->flags2, IPNET_IFF2_RANDOM_SEED);
            ipcom_srandom(seed);

            ipnet_ip4_lladdr_generate(netif);
        }
    }
}
#endif /* IPNET_USE_RFC3927 */

#if defined(IPNET_USE_RFC5227) || defined(IPNET_USE_RFC3927)

/*
 *===========================================================================
 *                     ipnet_ip4_has_routeable_addr
 *===========================================================================
 * Description: Returns the status whether a network interface has a routable
 *              (not link local) IPv4 address.
 * Parameters:  netif - A network interface.
 * Returns:     IP_TRUE if the network interface has a routable address
 *
 */
IP_STATIC Ip_bool
ipnet_ip4_has_routeable_addr(Ipnet_netif *netif)
{
    Ipnet_ip4_addr_entry *addr;

    for(addr = netif->inet4_addr_list; addr != IP_NULL; addr = addr->next)
    {
        if((addr->type == IPNET_ADDR_TYPE_UNICAST)
           && IP_BIT_ISFALSE(addr->flags, IPNET_IP4_ADDR_FLAG_LINK_LOCAL))
        {
            return IP_TRUE;
        }
    }
    return IP_FALSE;
}

/*
 *===========================================================================
 *                     ipnet_ip4_has_link_local_addr
 *===========================================================================
 * Description: Returns the status wether a network interface has a link local
 *              IPv4 address.
 * Parameters:  netif - A network interface.
 * Returns:     IP_TRUE if the network interface has a link local address
 *
 */
IP_STATIC Ip_bool
ipnet_ip4_has_link_local_addr(Ipnet_netif *netif)
{
    Ipnet_ip4_addr_entry *addr;

    for(addr = netif->inet4_addr_list; addr != IP_NULL; addr = addr->next)
    {
        if(IP_BIT_ISTRUE(addr->flags, IPNET_IP4_ADDR_FLAG_LINK_LOCAL))
        {
            return IP_TRUE;
        }
    }
    return IP_FALSE;
}


/*
 *===========================================================================
 *                     ipnet_ip4_acd_set_state
 *===========================================================================
 * Description: Change address conflict detection state of an address.
 * Parameters:  netif - A network interface.
 *              state - One of the IPNET_IP4_ACD_STATE_xxx constants
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_acd_set_state(Ipnet_ip4_addr_entry *addr, Ip_u8 state)
{
    Ipnet_ip4_addr_entry *lladdr = IP_NULL;
    Ip_u32 sec;
    Ip_u32 msec;
    Ipnet_netif *netif = addr->netif;
    Ipnet_data  *net = ipnet_pri_ptr();

#if IPNET_SYSLOG_PRIORITY >= IPCOM_LOG_INFO
    static const char *states[] = {
        "DISABLED",
        "INIT",
        "PROBE",
        "DEFEND",
        "ANNOUNCE",
        "ACTIVE",
    };
#endif

    ip_assert(state <= IPNET_IP4_ACD_STATE_MAX);
    /*
     * This state machine must be run by the primary instance.
     */
    ip_assert(ipnet_primary_instance_idx() == ipnet_this());

    if (netif->eth == IP_NULL)
        /* RFC3927 currently only implemented for Ethernet */
        return;

    if (addr->acd.state == state)
        return;

#ifdef IPNET_USE_RFC3927
    if ((IP_BIT_ISFALSE(netif->ipcom.flags, IP_IFF_UP)
         || (ipnet_ip4_has_routeable_addr(netif) == IP_TRUE))
        && (state == IPNET_IP4_ACD_STATE_INIT
            || state == IPNET_IP4_ACD_STATE_PROBE
            || state == IPNET_IP4_ACD_STATE_ANNOUNCE))
    {
        /*
         * RFC 3927, chapter 1.9
         *
         * A host with an address on a link can communicate with all
         * other devices on that link, whether those devices use
         * Link-Local addresses, or routable addresses.  For these
         * reasons, a host SHOULD NOT have both an operable routable
         * address and an IPv4 Link-Local address configured on the
         * same interface.
         */
        lladdr = ipnet_ip4_get_addr_entry(netif->inet4_lladdr.s_addr, netif->vr_index, netif);
        if((lladdr != IP_NULL))
        {
            IPCOM_LOG2(INFO,"IPv4: Routable address available. Remove dynamic link-local address %s on interface %s",
                       ipcom_inet_ntop(IP_AF_INET,
                                       &netif->inet4_lladdr.s_addr,
                                       net->log_buf,
                                       sizeof(net->log_buf)),
                       netif->ipcom.name);
            (void )ipnet_ip4_remove_addr(netif, netif->inet4_lladdr.s_addr);
            if(addr->ipaddr_n == netif->inet4_lladdr.s_addr)
                return;
        }
    }
#endif /* IPNET_USE_RFC3927 */

    switch (state)
    {
    case IPNET_IP4_ACD_STATE_DISABLED:
        ipnet_timeout_cancel(addr->acd.tmo);
        ipv4AddressEventHookProcess(IP_ADDREVENT_INET_DADSUCCESS, netif->ipcom.ifindex, 
                                         addr->ipaddr_n, (void *)netif->ipcom.link_addr);
        break;

    case IPNET_IP4_ACD_STATE_INIT:
        if ((addr->acd.state == IPNET_IP4_ACD_STATE_ACTIVE)
        	|| (IP_BIT_ISFALSE(netif->ipcom.flags,IP_IFF_RUNNING)))
            /* Continue with with address as active */
            return;
        ipv4AddressEventHookProcess(IP_ADDREVENT_INET_DADBEGIN, netif->ipcom.ifindex, 
                                         addr->ipaddr_n, (void *)netif->ipcom.link_addr);

        IP_BIT_SET(addr->flags, IPNET_IP4_ADDR_FLAG_TENTATIVE);

        IPCOM_LOG2(INFO,"IPv4: Performing address conflict detection for %s on %s",
                   ipcom_inet_ntop(IP_AF_INET,
                                   &addr->ipaddr_n,
                                   net->log_buf,
                                   sizeof(net->log_buf)),
                   netif->ipcom.name);
        /* RFC5227:2.1 A host MUST take precaution to limit the rate at which it probes for
         * new candidate addresses: If the host experiences MAX_CONFLICTS... */
        if (netif->conf.inet.ll_max_conflicts >= (int) netif->acd.conflicts)
        {
            /* Initially wait random time before first ARP Probe */
            msec = (Ip_u32)netif->conf.inet.ll_probe_wait * 1000;
            msec = (Ip_u32)ipcom_rand() % msec;
            ipnet_timeout_cancel(addr->acd.tmo);
            (void) ipnet_timeout_schedule(net,
                                          msec,
                                          (Ipnet_timeout_handler) ipnet_ip4_acd_probe_wait,
                                          addr,
                                          &addr->acd.tmo);
        }
        else
        {
            /* Too many conflicts on this interface. Enforce rate limit */
            IPCOM_LOG4(INFO,"IPv4: Too many address conflicts on %s, rate limit enforced for new candidate addresses",
                           netif->ipcom.name, addr->ipaddr_n, addr->acd.state, state);

            ipnet_timeout_cancel(addr->acd.tmo);
            if(ipcom_time(IP_NULL) - netif->acd.last_probe_time < (Ip_time_t)netif->conf.inet.ll_rate_limit_interval )
            {
                /* Rate limit is enforced on this interface due to too many conflicts
                 * Wait until try to probe again */
                sec = (Ip_u32) ((Ip_time_t)netif->conf.inet.ll_rate_limit_interval
                                - (ipcom_time(IP_NULL) - netif->acd.last_probe_time));
                (void) ipnet_timeout_schedule(net,
                                              sec * 1000,
                                              (Ipnet_timeout_handler) ipnet_ip4_acd_init_wait,
                                              addr,
                                              &addr->acd.tmo);
                return;

            }
            else
            {
                sec = (Ip_u32)netif->conf.inet.ll_rate_limit_interval;
                (void) ipnet_timeout_schedule(net,
                                              sec * 1000,
                                              (Ipnet_timeout_handler) ipnet_ip4_acd_probe_wait,
                                              addr,
                                              &addr->acd.tmo);
            }
        }
        break;

    case IPNET_IP4_ACD_STATE_PROBE:
        addr->acd.num = (Ip_u8) netif->conf.inet.ll_probe_num;
        netif->acd.last_probe_time = ipcom_time(IP_NULL);
        ipnet_ip4_acd_probe(addr);
        break;

    case IPNET_IP4_ACD_STATE_ANNOUNCE:
        /* Ok. No conflicts. We can now assign address and start using it */
        (void)ipnet_ip4_assign_addr(addr);
        addr->acd.num = (Ip_u8) netif->conf.inet.ll_announce_num;
        ipnet_ip4_acd_announce(addr);
        ipv4AddressEventHookProcess(IP_ADDREVENT_INET_DADSUCCESS, netif->ipcom.ifindex, 
                                         addr->ipaddr_n, (void *)netif->ipcom.link_addr);
        break;

    case IPNET_IP4_ACD_STATE_DEFEND:
        sec = (Ip_u32)netif->conf.inet.ll_defend_interval;
        ipnet_timeout_cancel(addr->acd.tmo);
        if (ipnet_timeout_schedule(net,
                                   sec * 1000,
                                   (Ipnet_timeout_handler) ipnet_ip4_acd_defend,
                                   addr,
                                   &addr->acd.tmo) == 0)
        {
            /* Send a single ARP announcement to defend this address */
            ipnet_arp_request(netif,
                              0,
                              addr->ipaddr_n,
                              IP_TRUE,
                              IP_NULL,
                              IP_NULL);
        }
        break;

    default:
        break;
    }

#if IPNET_SYSLOG_PRIORITY >= IPCOM_LOG_INFO
    if (addr->ipaddr_n)
        IPCOM_LOG3(INFO,
                   "IPv4: Changing state to %s for address %s on interface %s",
                   states[state],
                   ipcom_inet_ntop(IP_AF_INET,
                                   &addr->ipaddr_n,
                                   net->log_buf,
                                   sizeof(net->log_buf)),
                   netif->ipcom.name);
#endif

    addr->acd.state = state;
}


/*
 *===========================================================================
 *                    ipnet_ip4_acd_conflict
 *===========================================================================
 * Description: Conflict detected for the IPv4 address
 * Parameters:  addr - The address the conflict was detected on.
 * Returns:
 *
 */
IP_GLOBAL void
ipnet_ip4_acd_conflict(Ipnet_ip4_addr_entry *addr)
{
    Ipnet_netif *netif = addr->netif;
    Ip_bool defend = IP_FALSE;
    Ip_bool remove = IP_FALSE;

    if (addr->acd.state == IPNET_IP4_ACD_STATE_DISABLED)
    {
        return;
    }

    ipnet_timeout_cancel(addr->acd.tmo);

    if (netif->acd.conflicts < 255)
        /* Address conflicts since the interface was brought up */
        netif->acd.conflicts++;

    if ((addr->acd.state == IPNET_IP4_ACD_STATE_ANNOUNCE) ||
        (addr->acd.state == IPNET_IP4_ACD_STATE_ACTIVE) ||
        (addr->acd.state == IPNET_IP4_ACD_STATE_DEFEND))
    {
        /* Check if there is a reason to defend this address */
        Ipnet_ip4_addr_entry *addr_entry;
        Ipnet_socket         *sock;


        addr_entry = ipnet_ip4_get_addr_entry(addr->ipaddr_n,
                                              netif->vr_index,
                                              netif);
        if (addr_entry != IP_NULL)
            for (sock = addr_entry->socket_list;
                 sock != IP_NULL && defend == IP_FALSE;
                 sock = sock->addr_next)
                defend = (sock->ipcom.type == IP_SOCK_STREAM);
    }

    if (defend)
    {
        if(addr->acd.state == IPNET_IP4_ACD_STATE_DEFEND)
        {
            /* We received another conflict within DEFEND_INTERVAL seconds
             * for this address. It MUST be removed ( RFC5227,2.4(b) ) */
            IPCOM_LOG2(NOTICE, "IPv4: Repeated conflicts within DEFEND_INTERVAL for address %s on interface %s",
                       ipcom_inet_ntop(IP_AF_INET, &addr->ipaddr_n, ipnet_ptr()->log_buf, sizeof(ipnet_ptr()->log_buf)),
                       netif->ipcom.name);

            if(netif->conf.inet.delete_addr_on_duplicate_detect == IP_TRUE)
            {
                remove = IP_TRUE;
            }
        }
        else
            ipnet_ip4_acd_set_state(addr, IPNET_IP4_ACD_STATE_DEFEND);
    }
    else
    {
        IPCOM_LOG2(NOTICE,
                   "IPv4: Conflict for address %s on interface %s",
                   ipcom_inet_ntop(IP_AF_INET, &addr->ipaddr_n, ipnet_ptr()->log_buf, sizeof(ipnet_ptr()->log_buf)),
                   netif->ipcom.name);
        if(netif->conf.inet.delete_addr_on_duplicate_detect == IP_TRUE)
        {
            remove = IP_TRUE;
        }
        else
        {
            /* There is a conflicting address but the removal of it is disabled by sysvar.
             * Not removing the address violates RFC5227 and RFC3927 but could be usefull
             * in debug scenarios */
            switch(addr->acd.state)
            {
            case IPNET_IP4_ACD_STATE_PROBE:
                /* Conflict but announce it anyway */
                ipnet_ip4_acd_set_state(addr, IPNET_IP4_ACD_STATE_ANNOUNCE);
                break;
            case IPNET_IP4_ACD_STATE_ANNOUNCE:
            case IPNET_IP4_ACD_STATE_DEFEND:
                /* Conflict but make it active anyway */
                ipnet_ip4_acd_set_state(addr, IPNET_IP4_ACD_STATE_ACTIVE);
                break;
            default:
                break;
            }
        }
    }

    if (remove == IP_TRUE)
    {
        /* Announce conflict and remove address */
        IPNET_ROUTESOCK(ipnet_routesock_addr_conflict(netif, IP_AF_INET, addr));
        IPNET_NETLINKSOCK(ipnet_rtnetlink_ip4_addr_conflict(netif, addr));

        (void) ipnet_ip4_remove_addr(netif, addr->ipaddr_n);

#ifdef IPNET_USE_RFC3927
        if(IP_BIT_ISSET(addr->flags, IPNET_IP4_ADDR_FLAG_LINK_LOCAL))
        {
            /* Address conflict for link local address.
             * Reset seed bit for the interface. This will implicitly
             * also trigger a new link local address generation when needed*/
            IP_BIT_CLR(netif->flags2, IPNET_IFF2_RANDOM_SEED);

            /* Add new link local address if enabled */
            if(ipnet_ip4_lladdr_isenabled(netif) == IP_TRUE)
            {
                ipnet_ip4_lladdr_add(netif);
            }
        }
#endif
    }
}
#endif /* #if defined(IPNET_USE_RFC5227) || defined(IPNET_USE_RFC3927) */


/*
 *===========================================================================
 *                    ipnet_ip4_if_configure
 *===========================================================================
 * Description: Adds automatic IPv4 addresses for interfaces that just
 *              entered up state.
 * Parameters:  netif - The interface that is going to be configured.
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_if_configure(Ipnet_netif *netif)
{
    struct Ip_in_addr     addr;
    Ipnet_ip4_addr_entry *addr_entry;

    if (IP_BIT_ISSET(netif->flags2, IPNET_IFF2_NO_IPV4_SUPPORT))
        return;

#ifdef IPNET_USE_RFC5227
    if(netif->conf.inet.address_conflict_detect == IP_TRUE)
    {
        /* Initiate address conflict detection on all unicast
         * addresses on the interface */
        for (addr_entry = netif->inet4_addr_list;
             addr_entry != IP_NULL;
             addr_entry = addr_entry->next)
        {
            if(addr_entry->type == IPNET_ADDR_TYPE_UNICAST)
            {
                ipnet_ip4_acd_set_state(addr_entry, IPNET_IP4_ACD_STATE_INIT);
            }
        }
    }
#endif

    if (IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_MULTICAST))
    {
        /* Add the all multicast hosts address */
        (void) ipcom_inet_pton(IP_AF_INET, "224.0.0.1", &addr);
        (void)ipnet_ip4_add_addr2(netif,
                                  addr.s_addr,
                                  0,
                                  IPNET_IP4_ADDR_FLAG_AUTOMATIC,
                                  IPNET_ADDR_TYPE_MULTICAST);
    }

#ifdef IP_PORT_LKM
    if (netif->ipcom.type == IP_IFT_PPP)
    {
        Ipnet_ppp_peer  *p = netif->private_data;

        /* Setup the peer route */
        (void)ipnet_if_set_ipv4_ppp_peer(p,&p->peer4);
    }
#endif

#ifdef IPNET_USE_RFC3927
    /* RFC3927 currently only implemented for Ethernet */
    if((netif->eth != IP_NULL)
        && (!IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_LOOPBACK))
        && (ipnet_ip4_has_routeable_addr(netif) == IP_FALSE)
        && (ipnet_ip4_lladdr_isenabled(netif) == IP_TRUE))
    {
        /* Generate IPv4 link-local address */
        ipnet_ip4_lladdr_add(netif);
    }
#endif /* IPNET_USE_RFC3927 */

#ifdef IPNET_USE_RFC1256
    /* Initialize the RFC1256 specific portion of the netif */
    (void)ipnet_ip4_rfc1256_mode_update(netif->vr_index, netif);
#endif
}


/*
 *===========================================================================
 *                    ipnet_ip4_if_unconfigure
 *===========================================================================
 * Description: Removes all automatic IPv4 addresses.
 * Parameters:  netif - The interface that is going to be unconfigured.
 * Returns:
 *
 */
IP_STATIC void
ipnet_ip4_if_unconfigure(Ipnet_netif *netif)
{
    Ipnet_ip4_addr_entry *addr_entry;

    for (addr_entry = netif->inet4_addr_list;
         addr_entry != IP_NULL;
         addr_entry = addr_entry->next)
        IP_BIT_CLR(addr_entry->flags, IPNET_IP4_ADDR_FLAG_UPDATE_DONE);

    addr_entry = netif->inet4_addr_list;
    while (addr_entry != IP_NULL)
    {
        if (IP_BIT_ISSET(addr_entry->flags, IPNET_IP4_ADDR_FLAG_UPDATE_DONE)
            || IP_BIT_ISFALSE(addr_entry->flags, IPNET_IP4_ADDR_FLAG_AUTOMATIC))
        {
#ifdef IPNET_USE_RFC5227
            ipnet_ip4_acd_set_state(addr_entry, IPNET_IP4_ACD_STATE_DISABLED);
#endif
            IP_BIT_SET(addr_entry->flags, IPNET_IP4_ADDR_FLAG_UPDATE_DONE);
            addr_entry = addr_entry->next;
        }
        else
        {
            IP_BIT_SET(addr_entry->flags, IPNET_IP4_ADDR_FLAG_UPDATE_DONE);
            (void )ipnet_ip4_remove_addr(netif, addr_entry->ipaddr_n);
            addr_entry = netif->inet4_addr_list;
        }
    }

    ipnet_timeout_cancel(netif->igmpv1_querier_present_tmo);
#ifdef IPNET_USE_SOURCE_SPECIFIC_MCAST
    ipnet_timeout_cancel(netif->igmpv2_querier_present_tmo);
#endif

#ifdef IPNET_USE_RFC1256
    /* Initialize the RFC1256 specific portion of the netif */
    (void)ipnet_ip4_rfc1256_mode_update(netif->vr_index, netif);
#endif
}


/*
 *===========================================================================
 *                    ipnet_ip4_is_part_of_same_pkt
 *===========================================================================
 * Description: Returns if the two fragments are parts in the same packet.
 * Parameters:  frag1 - A IPv4 fragment.
 *              frag2 - Another IPv4 fragment.
 * Returns:     IP_TRUE or IP_FALSE.
 *
 */
IP_GLOBAL Ip_bool
ipnet_ip4_is_part_of_same_pkt(Ipcom_pkt *frag1, Ipcom_pkt *frag2)
{
    Ipnet_pkt_ip *ip4_hdr1;
    Ipnet_pkt_ip *ip4_hdr2;

    ip4_hdr1 = (Ipnet_pkt_ip *) &frag1->data[frag1->ipstart];
    ip4_hdr2 = (Ipnet_pkt_ip *) &frag2->data[frag2->ipstart];

    /*
     * RFC 791 p24
     *
     * The internet identification field (ID) is used together with
     * the source and destination address, and the protocol fields, to
     * identify datagram fragments for reassembly.
     */
    if (ip4_hdr1->id != ip4_hdr2->id
        || ip4_hdr1->p != ip4_hdr2->p
        || IPNET_IP4_GET_IPADDR(ip4_hdr1->src) != IPNET_IP4_GET_IPADDR(ip4_hdr2->src)
        || IPNET_IP4_GET_IPADDR(ip4_hdr1->dst) != IPNET_IP4_GET_IPADDR(ip4_hdr2->dst))
        return IP_FALSE;
    return IP_TRUE;
}



/*
 *===========================================================================
 *                   ipnet_icmp4_param_init
 *===========================================================================
 * Description: Initializes ICMP parameters using the IP packet that
 *              this node failed to process.
 * Parameters:  icmp_param - pointer to the ICMP parameters.
 *              pkt - IP packet that failed.
 * Returns:
 *
 */
IP_GLOBAL void
ipnet_icmp4_param_init(Ipnet_icmp_param *param,
                       Ipcom_pkt *pkt)
{
    const Ipnet_pkt_ip *iphdr;

    ipcom_memset(param, 0, sizeof(*param));

    param->vr = pkt->vr_index;

    iphdr = ipcom_pkt_get_iphdr(pkt);
    param->tos         = iphdr->tos;
    param->to.s_addr   = IPNET_IP4_GET_IPADDR((void *)iphdr->src);
    param->from.s_addr = IPNET_IP4_GET_IPADDR((void *)iphdr->dst);
    param->recv_pkt    = pkt;

    if (ipnet_ip4_get_addr_type(param->from.s_addr,
                                param->vr,
                                IP_NULL) != IPNET_ADDR_TYPE_UNICAST)
    {
#ifdef IPNET_USE_VRRP
        Ipnet_netif *netif = ipnet_if_indextonetif(pkt->vr_index,
                                                   pkt->ifindex);
        Ip_u8        vrrp_id = IPCOM_PKT_GET_VRID(pkt);
        struct Ip_in_addr  *from;

        if (vrrp_id != 0)
        {
            if(IP_NULL == netif)
            {
                IPCOM_LOG0(ERR, "ipnet_icmp4_param_init: netif is NULL, return!");
                return;
            }

            if (ipnet_vrrp_addr_vrid(netif, &(param->from), IP_AF_INET) == vrrp_id)
                /*
                 * Use the destination address is the packet that
                 * caused this ICMP to be sent since that address is
                 * an VRRP address this node is currently master for.
                 */
                return;

            from = ipnet_vrrp_get_addr_with_vrid(netif, vrrp_id, IP_AF_INET);
            if (IP_NULL != from)
            {
                /*
                 * Sent to this host via an VRRP link address, use a
                 * VRRP address in the response
                 */
                param->from.s_addr = from->s_addr;
                return;
            }
        }
#endif

        /* Let the stack select a source address */
        param->from.s_addr = IP_INADDR_ANY;
    }
}


/*
 *===========================================================================
 *                    ipnet_icmp4_rate_reseed
 *===========================================================================
 * Description: Reseeds the rate limit counter for ICMP packets.
 * Parameters:  peer_info - peer to reseed ICMP tokens for
 * Returns:
 *
 */
IP_STATIC void
ipnet_icmp4_rate_reseed(Ipnet_peer_info *peer_info)
{
    /*
     * This is a shared timeout hander. It is called starting inside
     * the critical region, and must exit it before returning.
     */
    peer_info->icmp_send_limit
        = (Ip_u32)ipnet_shared()->conf.inet.icmp_rate_limit_bucket_size;
    ipnet_exit_critical_region();
}


struct Ipnet_icmp_opt_copy
{
    void *ipopt;
    int   ipoptsize;
    int   ipoptflags;
};

IP_STATIC void
ipnet_icmp4_copyopts(Ipnet_icmp_param           *icmp_param,
                     struct Ipnet_icmp_opt_copy *copyopts,
                     struct Ipnet_ip4_sock_opts *opts,
                     Ipnet_ip4_layer_info       *ip4_info)
{
    Ipnet_pkt_ip_opt *opt = IP_NULL;

    /* No option copy allowed, or no options to copy */
    if (0 == copyopts->ipoptflags || IP_NULL == copyopts->ipopt)
        return;

    opts->len = 0;
    while (IP_NULL != (opt = ipnet_ip4_get_ip_opt_next(opt, copyopts->ipopt, copyopts->ipoptsize)))
    {
        if (0 == IP_BIT_ISSET(copyopts->ipoptflags, (1 << IP_IPOPT_NUMBER(opt->flag_class_num))))
            continue;

        switch (opt->flag_class_num)
        {
        case IP_IPOPT_RR:
            /* Copy entire option */
            ipcom_memcpy(&opts->opts[opts->len], opt, opt->len);
            /* Increase size of option block */
            opts->len += opt->len;
            break;

        case IP_IPOPT_LSRR:
        case IP_IPOPT_SSRR:
            {
                Ip_u8 *ndata = &opts->opts[opts->len];
                Ip_u8 *odata = (Ip_u8 *)opt;
                int  ooff = (odata[2]>39 ? 39 : odata[2]) - 5;

                /* Source routing - first sanity */
                if (icmp_param->type == IPNET_ICMP4_TYPE_PARAMPROB)
                {
                    int start = IPNET_IP_HDR_SIZE + (int)((char *)opt - (char *)copyopts->ipopt);

                    /* Dont include source routing option if we've gotten a parameter problem pointing
                     * into this option */
                    if (icmp_param->data.param_pointer >= start &&  icmp_param->data.param_pointer < (start + opt->len))
                        break;
                }

                ndata[0] = odata[0];
                ndata[1] = 3;
                ndata[2] = 4;

                for (; ooff > 0; ooff -= 4, ndata[1] = (Ip_u8)(ndata[1] + 4))
                    ipcom_memcpy(&ndata[ndata[1]], &odata[ooff], 4);

                /* Add final destination */
                ipcom_memcpy(&ndata[ndata[1]], &icmp_param->to.s_addr, 4);
                ndata[1] = (Ip_u8)(ndata[1] + 4);

                /* Increase size of option block */
                opts->len += ndata[1];
            }
            break;

        case IP_IPOPT_TIMESTAMP:
            /* Copy entire option */
            ipcom_memcpy(&opts->opts[opts->len], opt, opt->len);
            /* Increase size of option block */
            opts->len += opt->len;
            break;
        }
    }

    /* Finalize padding */
    if (0 != opts->len)
    {
        while (opts->len & 0x3)
            opts->opts[opts->len++] = IP_IPOPT_END;
        ip4_info->opts = opts;
    }
}

/*
 *===========================================================================
 *                    ipnet_icmp4_send
 *===========================================================================
 * Description: Creates and send a ICMPv4 message.
 * Parameters:  The parameters for to create the ICMP message.
 * Returns:     0 = success, <0 error code.
 *
 */
IP_GLOBAL int
ipnet_icmp4_send(Ipnet_icmp_param *icmp_param, Ip_bool is_igmp)
{
    Ipnet_pkt_icmp        *icmp;
    Ipcom_pkt             *pkt;
    Ip_bool                request_reply_msg = IP_FALSE;
    Ipnet_netif           *recv_netif = IP_NULL;
    Ip_u16                 vr;
    Ipnet_ip4_layer_info   ip4_info;
    Ipnet_dst_cache       *dst;
    struct Ipnet_ip4_sock_opts  opts;
    struct Ipnet_icmp_opt_copy  copyopts  = { IP_NULL, 0,  (1 << IP_IPOPT_NUMBER(IP_IPOPT_SSRR)) | (1 << IP_IPOPT_NUMBER(IP_IPOPT_LSRR)) };
    Ipnet_data            *net = ipnet_ptr();

    vr = icmp_param->vr;
    if (ipnet_route_is_virtual_router_valid(vr) == IP_FALSE)
    {
        /* The virtual router has been deleted */
        IPCOM_LOG4(NOTICE,
                   "IPv4: send ICMP type:%d code:%d to %s dropped since VR#%u has been removed",
                   icmp_param->type,
                   icmp_param->code,
                   ipcom_inet_ntop(IP_AF_INET,
                                   &icmp_param->to,
                                   net->log_buf,
                                   sizeof(net->log_buf)),
                   vr);
        return -IP_ERRNO_ENXIO;
    }

    if (is_igmp)
    {
        /* Not on IGMP messages */
        copyopts.ipoptflags  = 0;
        if (icmp_param->type == IPNET_IGMP4_TYPE_V3_MEMBERSHIP_REPORT)
            icmp_param->tos = IPNET_IGMPV3_TOS;
    }
    else
    {
        /*
         * Set the TOS field according to RFC 1812 chapter 4.3.2.5
         */
        switch (icmp_param->type)
        {
        case IPNET_ICMP4_TYPE_DST_UNREACHABLE:
        case IPNET_ICMP4_TYPE_REDIRECT:
        case IPNET_ICMP4_TYPE_TIME_EXCEEDED:
        case IPNET_ICMP4_TYPE_PARAMPROB:
            icmp_param->tos = IPNET_ICMP4_TOS_INTERNETWORK_CONTROL;
            break;
        default:
            /* Use th TOS storead in icmp_param->tos */
            break;
        }

        if (icmp_param->type == IPNET_ICMP4_TYPE_PARAMPROB
            && ipnet_ip4_get_offset(icmp_param->recv_pkt) > 0)
        {
            /*
             * RFC 792
             * ...
             * Also ICMP messages are only sent about errors in
             * handling fragment zero of fragmented datagrams.
             * ...
             * This not the first fragment, ignore error.
             */
            return 0;
        }
    }

    /*
     * Get the destination cache entry to use when sending this
     * ICMP/IGMP message
     */
    /* Convert to flow spec */
    dst = ipnet_ip4_dst_cache_get_tx(net,
                                     vr,
                                     &icmp_param->to,
                                     &icmp_param->from,
                                     icmp_param->tos,
                                     icmp_param->ifindex,
                                     (icmp_param->recv_pkt ? icmp_param->recv_pkt->ifindex : 0));
    if (dst == ipnet_dst_cache_blackhole(net)
        && icmp_param->ifindex == 0)
    {
        /*
         * Allow any egress interface since the egress interface was
         * not a hard requirement.
         */
        dst = ipnet_ip4_dst_cache_get_tx(net,
                                         vr,
                                         &icmp_param->to,
                                         &icmp_param->from,
                                         icmp_param->tos,
                                         0,
                                         0);
    }


    if (icmp_param->recv_pkt != IP_NULL)
        recv_netif = ipnet_if_indextonetif(vr,
                                           icmp_param->recv_pkt->ifindex);

    if (!is_igmp)
    {
        switch (icmp_param->type)
        {
        case IPNET_ICMP4_TYPE_TIME_EXCEEDED:
            if (recv_netif == IP_NULL
                || !recv_netif->conf.inet.icmp_send_time_exceeded)
                /* Silently ignore */
                return 0;
            break;

        case IPNET_ICMP4_TYPE_DST_UNREACHABLE:
            if (recv_netif == IP_NULL
                || (!recv_netif->conf.inet.icmp_send_dst_unreach
                    && ipcom_strncmp(recv_netif->ipcom.name, "lo0", 3) != 0))
                /* Silently ignore */
                return 0;

            if (icmp_param->code == IPNET_ICMP4_CODE_DST_UNREACH_NET
                || icmp_param->code == IPNET_ICMP4_CODE_DST_UNREACH_HOST)
            {
                IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsInNoRoutes, 1);
                IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsInNoRoutes, 1, recv_netif, ipnet_instance_idx(net));
            }
            break;

        case IPNET_ICMP4_TYPE_ROUTER_SOLICIT:
            copyopts.ipoptflags  = 0;
            break;
        case IPNET_ICMP4_TYPE_ROUTER_ADVERT:
            copyopts.ipoptflags  = 0;
            request_reply_msg = IP_TRUE;
            break;
        case IPNET_ICMP4_TYPE_ECHO_REPLY:
            copyopts.ipoptflags |= (1 << IP_IPOPT_NUMBER(IP_IPOPT_TIMESTAMP)) | (1 << IP_IPOPT_NUMBER(IP_IPOPT_RR));
            request_reply_msg = IP_TRUE;
            break;
        case IPNET_ICMP4_TYPE_TSTAMP_REPLY:
            copyopts.ipoptflags |= (1 << IP_IPOPT_NUMBER(IP_IPOPT_TIMESTAMP));
            request_reply_msg = IP_TRUE;
            break;
        case IPNET_ICMP4_TYPE_MASK_REPLY:
            request_reply_msg = IP_TRUE;
            break;

        default:
            break;
        }
    }

    /*
     * Under memory exhaustion conditions dst may be the singleton blackhole
     * destination cache entry, which has no peer_info.
     */
    if (dst->peer_info &&
        !ipnet_is_loopback(vr,
                           (icmp_param->ifindex
                            ? icmp_param->ifindex
                            : (recv_netif
                               ? recv_netif->ipcom.ifindex
                               : 0))))
    {
        Ipnet_peer_info *peer_info = dst->peer_info;
        Ip_u32 icmp_send_limit;

        ipnet_enter_critical_region();
        if (peer_info->icmp_send_limit_tmo == IP_NULL)
        {
            struct Ipnet_inet_conf *conf = &ipnet_shared()->conf.inet;

            if (conf->icmp_rate_limit_interval)
                (void) ipnet_shared_timeout_schedule(net,
                                                     conf->icmp_rate_limit_interval,
                                                     (Ipnet_timeout_handler) ipnet_icmp4_rate_reseed,
                                                     peer_info,
                                                     &peer_info->icmp_send_limit_tmo);
            else
                /* Disable ratelimit */
                peer_info->icmp_send_limit = ~0u;
        }
        icmp_send_limit = peer_info->icmp_send_limit;
        if (icmp_send_limit > 0)
            --peer_info->icmp_send_limit;
        ipnet_exit_critical_region();

        if (icmp_send_limit == 0)
        {
            IPCOM_LOG3(DEBUG2,
                       "IPv4: send ICMPv4 type:%d code:%d to %s dropped due to rate limit policy",
                       icmp_param->type,
                       icmp_param->code,
                       ipcom_inet_ntop(IP_AF_INET,
                                       &dst->flow_spec.to,
                                       net->log_buf,
                                       sizeof(net->log_buf)));
            goto abort_send;
        }
    }

    if (dst->flow_spec.to.in.s_addr == IP_INADDR_ANY
        || dst->neigh == IP_NULL)
        /* We have read back our own broadcast when running as DHCP client */
        return IPNET_ERRNO(EINVAL);

    IPCOM_WV_MARKER_1 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_VERBOSE, 1, 2, IPCOM_WV_NETDEVENT_START,
                       ipnet_icmp4_send, IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
    IPNET_STATS(net, icmp4_send++);

    ipcom_memset(&ip4_info, 0, sizeof(ip4_info));
    if (is_igmp)
    {
        ip_assert(icmp_param->type == IPNET_IGMP4_TYPE_V1_MEMBERSHIP_REPORT
                  || icmp_param->type == IPNET_IGMP4_TYPE_V2_MEMBERSHIP_REPORT
                  || icmp_param->type == IPNET_IGMP4_TYPE_V3_MEMBERSHIP_REPORT
                  || icmp_param->type == IPNET_IGMP4_TYPE_V2_LEAVE_GROUP);
        ip4_info.proto = IP_IPPROTO_IGMP;
    }
    else
    {
        ip_assert(icmp_param->type == IPNET_ICMP4_TYPE_TIME_EXCEEDED
                  || icmp_param->type == IPNET_ICMP4_TYPE_REDIRECT
                  || icmp_param->type == IPNET_ICMP4_TYPE_DST_UNREACHABLE
                  || icmp_param->type == IPNET_ICMP4_TYPE_PARAMPROB
                  || icmp_param->type == IPNET_ICMP4_TYPE_ECHO_REPLY
                  || icmp_param->type == IPNET_ICMP4_TYPE_ROUTER_SOLICIT
                  || icmp_param->type == IPNET_ICMP4_TYPE_ROUTER_ADVERT
                  || icmp_param->type == IPNET_ICMP4_TYPE_TSTAMP_REPLY
                  || icmp_param->type == IPNET_ICMP4_TYPE_MASK_REPLY);
        ip4_info.proto = IP_IPPROTO_ICMP;
    }

    /*
     * If TTL has been specified, set
     */
    if (icmp_param->ttl != 0)
        ip4_info.ttl = icmp_param->ttl;
    else
    {
        if (is_igmp)
            /*
             * IGMP messages should only be link-local.
             */
            ip4_info.ttl = 1;
        else
            ip4_info.ttl = (Ip_u8) dst->neigh->netif->conf.inet.base_hop_limit;
    }

    if (request_reply_msg)
    {
        Ipnet_pkt_ip *ip_hdr;
#ifdef IP_PORT_LKM
        /*
         * Clone the received packet and just change the type
         */
        pkt = ipnet_pkt_clone(icmp_param->recv_pkt, IP_TRUE);
        ipcom_pkt_free(icmp_param->recv_pkt);

        if (pkt == IP_NULL)
        {
            IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_CRITICAL,
                              1, 3, IPCOM_WV_NETDEVENT_CRITICAL, IPCOM_WV_NETD_SEND,
                              ipnet_icmp4_send, IPCOM_WV_NETD_NOBUFS,
                              IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
            IPNET_STATS(net, icmp4_send_nomem++);
            IPCOM_MIB2(net, icmpOutErrors++);
            IPCOM_MIB2_SYSWI_U32_ADD(net, v4, icmpStatsOutErrors, 1);
            return IPNET_ERRNO(ENOMEM);
        }

#else
        /*
         * Use the received packet and just change the type
         */
        pkt = icmp_param->recv_pkt;
#endif
        pkt->flags = IPCOM_PKT_FLAG_ALLOC | IPCOM_PKT_FLAG_PROGRESS;
        pkt->ifindex = 0;
        icmp_param->recv_pkt = IP_NULL;

        ip_hdr = ipcom_pkt_get_iphdr(pkt);
        /* Retain the option block */
        if (0 != (copyopts.ipoptsize = IPNET_IP4_GET_OPTS_OCTET_LEN(ip_hdr)))
            copyopts.ipopt = (char *)ip_hdr + IPNET_IP_HDR_SIZE;
    }
    else
    {
        /*
         * Create a reply packet.
         */
        pkt = ipcom_pkt_malloc(dst->path_mtu, IP_FLAG_FC_STACKCONTEXT);
        if (pkt == IP_NULL)
        {
            IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_CRITICAL,
                              1, 4, IPCOM_WV_NETDEVENT_CRITICAL, IPCOM_WV_NETD_SEND,
                              ipnet_icmp4_send, IPCOM_WV_NETD_NOBUFS,
                              IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
            IPNET_STATS(net, icmp4_send_nomem++);
            IPCOM_MIB2(net, icmpOutErrors++);
            IPCOM_MIB2_SYSWI_U32_ADD(net, v4, icmpStatsOutErrors, 1);
            return IPNET_ERRNO(ENOMEM);
        }

        ipnet_pkt_set_stack_instance(pkt, net);

        IP_BIT_SET(pkt->flags, IPCOM_PKT_FLAG_NONBLOCKING);
        /*
         * Set pkt->start to the beginning of ICMPv4 data
         */
        pkt->start = ipcom_conf_max_link_hdr_size + IPNET_IP_HDR_SIZE;
        /*
         * Make room for the ICMPv4 header
         */
        pkt->end = pkt->start + IPNET_ICMP_HDR_SIZE;
    }

    icmp = ipcom_pkt_get_data(pkt, 0);
    if (request_reply_msg == IP_FALSE)
        ipcom_memset(&icmp->data, 0, sizeof(icmp->data));
    pkt->vr_index = vr;

    /*
     * Add the IP header + Min 64 bits of the failing packet (RFC 792)
     */
    if (!is_igmp
        && (icmp_param->type == IPNET_ICMP4_TYPE_DST_UNREACHABLE
            || icmp_param->type == IPNET_ICMP4_TYPE_REDIRECT
            || icmp_param->type == IPNET_ICMP4_TYPE_PARAMPROB
            || icmp_param->type == IPNET_ICMP4_TYPE_TIME_EXCEEDED))
    {
        Ipcom_pkt    *failing_pkt = icmp_param->recv_pkt;
        Ipnet_pkt_ip *ip_hdr;
        int           len;
        Ip_bool       discard_pkt;

        if (failing_pkt->end < failing_pkt->ipstart)
        {
            ipcom_pkt_free(pkt);
            return IPNET_ERRNO(EINVAL);
        }

        ip_hdr = ipcom_pkt_get_iphdr(failing_pkt);

        if (ip_hdr->off & IPNET_OFF_MASK)
            discard_pkt = IP_TRUE;
        else if (ip_hdr->p == IP_IPPROTO_ICMP)
        {
            Ip_u8 icmp_type = *((Ip_u8*)ip_hdr + IPNET_IP4_GET_HDR_OCTET_LEN(ip_hdr));

            discard_pkt = (icmp_type != IPNET_ICMP4_TYPE_ECHO_REQUEST
                           && icmp_type != IPNET_ICMP4_TYPE_ECHO_REPLY
                           && icmp_type != IPNET_ICMP4_TYPE_TSTAMP_REQUEST
                           && icmp_type != IPNET_ICMP4_TYPE_TSTAMP_REPLY);
        }
        else
            discard_pkt = IP_FALSE;

        if (discard_pkt)
        {
            /*
             * RFC 792 p1
             * To avoid the infinite regress of messages about
             * messages etc., no ICMP messages are sent about ICMP
             * messages. Also ICMP messages are only sent about errors
             * in handling fragment zero of fragemented datagrams.
             *
             * Allow ECHO request/reply since they are sometimes used
             * to probe for PMTU, which requires host unreachable
             * message to be sent.
             */
            ipcom_pkt_free(pkt);
            return 0;
        }

        /* Retain the option block */
        if (0 != (copyopts.ipoptsize = IPNET_IP4_GET_OPTS_OCTET_LEN(ip_hdr)))
            copyopts.ipopt = (char *)ip_hdr + IPNET_IP_HDR_SIZE;

        len = IP_MIN(pkt->maxlen - pkt->end, failing_pkt->end - failing_pkt->ipstart);
        len = IP_MIN(len, IPNET_IP_HDR_SIZE + IPNET_ICMP_HDR_SIZE + IPNET_ICMP_MAX_SIZE);
        ipcom_memcpy(&pkt->data[pkt->end],
                     ipcom_pkt_get_iphdr(failing_pkt),
                     (Ip_size_t)len);

        if (icmp_param->type == IPNET_ICMP4_TYPE_REDIRECT)
        {
            /*
             * ANVL wants the TTL updated in the copy of the redirected packet
             * returned in the ICMP redirect message.  Make sure not to
             * update the TTL/checksum in the original packet here, which will
             * be sent on to its destination with its TTL/checksum adjusted
             * by other code. VXW6-73491, VXW6-19833.
             */
            ip_hdr = (Ipnet_pkt_ip *)&pkt->data[pkt->end];
            IP_INCREMENTAL_CHECKSUM(ip_hdr);
        }

        pkt->end += len;
    }

    /*
     * ICMP/IGMP type specific data.
     */
    if (is_igmp)
        switch (icmp_param->type)
        {
        case IPNET_IGMP4_TYPE_V1_MEMBERSHIP_REPORT:
        case IPNET_IGMP4_TYPE_V2_MEMBERSHIP_REPORT:
        case IPNET_IGMP4_TYPE_V2_LEAVE_GROUP:
            ip_assert(icmp_param->data.igmp_addr_entry != IP_NULL);
            ipcom_memcpy(icmp->data.igmp.multicast_addr,
                         &icmp_param->data.igmp_addr_entry->ipaddr_n,
                         sizeof(struct Ip_in_addr));
            if (icmp_param->type != IPNET_IGMP4_TYPE_V1_MEMBERSHIP_REPORT)
                IP_BIT_SET(ip4_info.flags, IPNET_IP4_OPF_ROUTER_ALERT);
            break;

#ifdef IPNET_USE_SOURCE_SPECIFIC_MCAST
        case IPNET_IGMP4_TYPE_V3_MEMBERSHIP_REPORT:
            ipnet_igmpv3_create_membership_report(pkt, icmp_param->data.igmp_addr_entry);
            /*
             * RFC 3376 state that TOS of all IGMPv3 messages must be 0xc0
             * and that they must include the router alert option.
             */
            icmp_param->tos = 0xc0;
            IP_BIT_SET(ip4_info.flags, IPNET_IP4_OPF_ROUTER_ALERT);
            break;
#endif /* IPNET_USE_SOURCE_SPECIFIC_MCAST */

        default:
            break;
        }
    else
        switch (icmp_param->type)
        {
        case IPNET_ICMP4_TYPE_DST_UNREACHABLE:
            if (icmp_param->code == IPNET_ICMP4_CODE_DST_NEEDFRAG)
                IP_SET_HTONL(icmp->data.failing_pkt.next_hop_mtu, icmp_param->data.max_path_mtu);
            break;

        case IPNET_ICMP4_TYPE_REDIRECT:
            ip_assert(icmp_param->data.gateway_addr != IP_NULL);
            ipcom_memcpy(icmp->data.redirect.gateway_addr,
                         icmp_param->data.gateway_addr,
                         sizeof(struct Ip_in_addr));
            break;

        case IPNET_ICMP4_TYPE_PARAMPROB:
            icmp->data.param.pointer = icmp_param->data.param_pointer;
            break;

        case IPNET_ICMP4_TYPE_TSTAMP_REPLY:
            do
            {
                Ip_u32 millisec = (Ip_u32)ipnet_msec_now(net);
                IP_SET_HTONL(icmp->data.timestamp.receive, millisec);
                IP_SET_HTONL(icmp->data.timestamp.transmit, millisec);
                break;
            } while (0);
            /* Fall through */
        case IPNET_ICMP4_TYPE_ECHO_REPLY:
            break;

        default:
            break;
        }

    /* */
    ipnet_icmp4_copyopts(icmp_param, &copyopts, &opts, &ip4_info);

    icmp->type  = (Ip_u8)icmp_param->type;
    icmp->code  = (Ip_u8)icmp_param->code;
    icmp->cksum = 0;
    icmp->cksum = ipcom_in_checksum_pkt(pkt, 0);

    /*
     * Update MIB-2 stats
     */
    IPCOM_MIB2(net, icmpOutMsgs++);
    IPCOM_MIB2_SYSWI_U32_ADD(net, v4, icmpStatsOutMsgs, 1);
    IPCOM_MIB2_SYSWI_U32_ADD(net, v4, icmpMsgStatsOutPkts[icmp->type], 1);
    switch (icmp->type)
    {
    case IPNET_ICMP4_TYPE_ECHO_REPLY :
        IPCOM_MIB2(net, icmpOutEchoReps++);
        break;
    case IPNET_ICMP4_TYPE_DST_UNREACHABLE :
        IPCOM_MIB2(net, icmpOutDestUnreachs++);
        break;
    case IPNET_ICMP4_TYPE_SOURCEQUENCH :
        IPCOM_MIB2(net, icmpOutSrcQuenchs++);
        break;
    case IPNET_ICMP4_TYPE_REDIRECT :
        IPCOM_MIB2(net, icmpOutRedirects++);
        break;
    case IPNET_ICMP4_TYPE_ECHO_REQUEST :
        /* Handled separately */
        break;
    case IPNET_ICMP4_TYPE_TIME_EXCEEDED :
        IPCOM_MIB2(net, icmpOutTimeExcds++);
        break;
    case IPNET_ICMP4_TYPE_PARAMPROB :
        IPCOM_MIB2(net, icmpOutParmProbs++);
        break;
    case IPNET_ICMP4_TYPE_TSTAMP_REQUEST :
        IPCOM_MIB2(net, icmpOutTimestamps++);
        break;
    case IPNET_ICMP4_TYPE_TSTAMP_REPLY :
        IPCOM_MIB2(net, icmpOutTimestampReps++);
        break;
    case IPNET_ICMP4_TYPE_MASK_REQUEST :
        IPCOM_MIB2(net, icmpOutAddrMasks++);
        break;
    case IPNET_ICMP4_TYPE_MASK_REPLY :
        IPCOM_MIB2(net, icmpOutAddrMaskReps++);
        break;
    default:
        break;
    }

    IPNET_IP4_SET_LAYER_INFO(pkt, &ip4_info);
    return ipnet_dst_cache_tx(dst, pkt);

  abort_send:
    if (request_reply_msg)
    {
        ipcom_pkt_free(icmp_param->recv_pkt);
        icmp_param->recv_pkt = IP_NULL;
    }
    return 0;
}



/*
 *===========================================================================
 *                    ipnet_icmp4_send_host_unreachable
 *===========================================================================
 * Description: Sends a ICMP host unreachable
 * Parameters:  pkt - Packet that could not be sent.
 * Returns:
 *
 */
IP_GLOBAL void
ipnet_icmp4_send_host_unreachable(Ipcom_pkt *pkt)
{
    ipnet_ip4_dst_unreachable(pkt, IP_ERRNO_EHOSTUNREACH);
}


/*
 *===========================================================================
 *                   ipnet_icmp4_send_port_unreachable
 *===========================================================================
 * Description: No one listened to the UDP port used as destination
 *              port in the passed UDP packet. Send back a UDP port
 *              unreachable message.
 * Parameters:  udp_pkt - UDP datagram for which no listener existed
 * Returns:
 *
 */
IP_GLOBAL void
ipnet_icmp4_send_port_unreachable(Ipcom_pkt *udp_pkt)
{
    Ipnet_icmp_param icmp_param;
#if defined(IPNET_DEBUG) || defined(IPNET_STATISTICS) || defined(IPNET_DEBUG)
    Ipnet_data      *net = ipnet_pkt_get_stack_instance(udp_pkt);
#endif

    ipnet_icmp4_param_init(&icmp_param, udp_pkt);
    icmp_param.type = IPNET_ICMP4_TYPE_DST_UNREACHABLE;
    icmp_param.code = IPNET_ICMP4_CODE_DST_UNREACH_PORT;
    (void) ipnet_icmp4_send(&icmp_param, IP_FALSE);

    IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_WARNING,
                      1, 40, IPCOM_WV_NETDEVENT_WARNING, IPCOM_WV_NETD_RECV,
                      ipnet_icmp4_send_port_unreachable, IPCOM_WV_NETD_NOPORT,
                      IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
    IPNET_STATS(net, udp4_input_err++);
}



#ifdef IPNET_USE_SOURCE_SPECIFIC_MCAST
/*
 *===========================================================================
 *                  ipnet_igmpv3_add_source_to_group_record
 *===========================================================================
 * Description: Possibly adds one source address to a group record.
 * Parameters:  source_addr - The source address that might be added.
 *              d - Callback data.
 * Returns:
 *
 */
IP_STATIC void
ipnet_igmpv3_add_source_to_group_record(Ip_u32 *source_addr,
                                        struct Ipnet_igmpv3_report_for_each_data *d)
{
    if (d->set != IP_NULL)
    {
        if (ipcom_set_contains(d->set, source_addr) == IP_FALSE)
            /* Do not add this address, since it is not part of the interface filter */
            return;
    }

    /* This source should be added to the message */
    if (d->pkt->maxlen - d->pkt->end < (int) sizeof(*source_addr))
    {
        /* TODO: create more messages */
        return;
    }
    d->pkt->end += (int) ip_ssizeof(*source_addr);
    IPNET_IP4_SET_IPADDR(&d->group_record->source_addr[d->group_record->number_of_sources],
                         *source_addr);
    d->group_record->number_of_sources++;
}


/*
 *===========================================================================
 *                  ipnet_igmpv3_create_membership_report
 *===========================================================================
 * Description: Creates a IGMPv3 membership report.
 * Parameters:  pkt - The packet where the report should be stored.
 *              addr_entry - The multicast address entry a report should
 *                           be created for.
 * Returns:
 *
 */
IP_STATIC void
ipnet_igmpv3_create_membership_report(Ipcom_pkt *pkt, Ipnet_ip4_addr_entry *addr_entry)
{
    struct Ipnet_igmpv3_report_for_each_data d;
    Ipnet_pkt_igmpv3_report *report;
    Ipcom_set               *set;

    report = ipcom_pkt_get_data(pkt, 0);
    report->number_of_group_records = ip_htons(1);

    d.pkt          = pkt;
    d.addr_entry   = addr_entry;
    d.set          = IP_NULL;
    d.group_record = &report->group_records[0];
    d.group_record->aux_data_len      = 0;
    d.group_record->number_of_sources = 0;
    IPNET_IP4_SET_IPADDR(&d.group_record->multicast_addr, addr_entry->ipaddr_n);
    pkt->end = pkt->start + IPNET_IGMPV3_REPORT_MIN_SIZE;

    switch (addr_entry->mcast.report_type)
    {
    case IPNET_MCAST_REPORT_SPECIFIC_QUERY:
        set = addr_entry->mcast.specific_query_sources;
        if (set == IP_NULL || set->user == IPNET_MCAST_RECORD_TYPE_IS_EXCLUDE)
            goto current_state_record;

        /* "Current-State Record" as response to group and source specific query */
        ip_assert(set->user == IPNET_MCAST_RECORD_TYPE_IS_INCLUDE);
        d.set = addr_entry->mcast.filter;
        d.group_record->record_type = (Ip_u8) d.set->user;
        break;
    case IPNET_MCAST_REPORT_FILTER_CHANGE:
        /* "Filter-Mode-Change Record" or "Source-List-Change Record" */
        set = addr_entry->mcast.filter_change_sources;
        if (set == IP_NULL)
            goto current_state_record;

        d.group_record->record_type = (Ip_u8) set->user;
        break;
    case IPNET_MCAST_REPORT_GENERAL_QUERY:
        /* "Current-State Record" */
    current_state_record:
        set = addr_entry->mcast.filter;
        if (set == IP_NULL)
        {
            /* Treat as mode IS_EXCLUDE with empty set */
            d.group_record->record_type = IPNET_MCAST_RECORD_TYPE_IS_EXCLUDE;
            return;
        }
        d.group_record->record_type = (Ip_u8) set->user;
        break;
    default:
        return;
    }

    ipcom_set_for_each(set,
                       (Ipcom_set_foreach_cb_func) ipnet_igmpv3_add_source_to_group_record,
                       &d);
    d.group_record->number_of_sources = ip_htons(d.group_record->number_of_sources);
}



/*
 *===========================================================================
 *                  ipnet_igmpv3_build_if_filter
 *===========================================================================
 * Description: Builds filter for multicast address maddr.
 * Parameters:  sockfd - pointer to the socket descriptor which included
 *              and/or excluded sources on this multicast address now will
 *              be included in the filter.
 *              maddr - multicast address to build filter for.
 * Returns:
 *
 */
IP_STATIC void
ipnet_igmpv3_build_if_filter(Ipnet_socket **sockp, Ipnet_ip4_addr_entry *maddr)
{
    Ipnet_ip4_sock_mcast_data *mcast_data;
    Ipnet_socket              *sock = *sockp;

    if (sock == IP_NULL || ipnet_fd_to_sock(sock->ipcom.fd) != sock)
    {
        /* The socket should always be removed from the set if closed */
        IP_PANIC();
        return;
    }

    mcast_data = *ipnet_sock_ip4_get_mcast_data(sock,
                                                ipnet_ip4_addr_to_netif(maddr),
                                                (struct Ip_in_addr *) &maddr->ipaddr_n);
    if (mcast_data == IP_NULL)
    {
        /* The socket must not be in the socket set if is has not joined a group */
        IP_PANIC2();
        return;
    }

    ipnet_mcast_build_if_filter(&maddr->mcast, mcast_data->sources);
}


/*
 *===========================================================================
 *                  ipnet_igmpv3_report_change
 *===========================================================================
 * Description: Creates a report about filter change on a multicast address.
 * Parameters:  netif - The inteface the multicast address is/was assigned to
 *              group - An multicast address.
 * Returns:
 *
 */
IP_GLOBAL void
ipnet_igmpv3_report_change(Ipnet_netif *netif, struct Ip_in_addr *group)
{
    Ipnet_ip4_addr_entry *addr_entry;

    addr_entry = ipnet_ip4_get_addr_entry(group->s_addr, netif->vr_index, netif);
    if (addr_entry == IP_NULL)
        /* No longer member of this multicast address on this interface */
        return;

    if (ipnet_mcast_build_source_change_report(&addr_entry->mcast,
                                               (Ipcom_set_foreach_cb_func) ipnet_igmpv3_build_if_filter,
                                               addr_entry))
    {
        addr_entry->mcast.filter_change_resend_count = (Ip_u8) netif->igmp_robustness_variable;
        ipnet_igmp_report_filter_change(addr_entry);
    }
}
#endif /* IPNET_USE_SOURCE_SPECIFIC_MCAST */


/*
 *===========================================================================
 *                    ipnet_igmp_host_compatibility_mode
 *===========================================================================
 * Description: Returns the IGMP mode the host is running at on the specified
 *              interface.
 * Parameters:  netif - The interface that joined the multicast group.
 * Returns:     IPNET_IGMP_V[1|2|3}_MODE
 *
 */
IP_STATIC int
ipnet_igmp_host_compatibility_mode(Ipnet_netif *netif)
{
    int compat_version;
    int maximum_igmp_version = netif->conf.inet.igmp_max_version;

#ifdef IPNET_USE_SOURCE_SPECIFIC_MCAST
    compat_version = IPNET_IGMPV3_MODE;
#else
    compat_version = IPNET_IGMPV2_MODE;
#endif

    if (netif->igmpv1_querier_present_tmo != IP_NULL)
        compat_version = IPNET_IGMPV1_MODE;
#ifdef IPNET_USE_SOURCE_SPECIFIC_MCAST
    else if (netif->igmpv2_querier_present_tmo != IP_NULL)
        compat_version = IPNET_IGMPV2_MODE;
#endif

    return IP_MIN(compat_version, maximum_igmp_version);
}


/*
 *===========================================================================
 *                    ipnet_igmp_should_send_message
 *===========================================================================
 * Description: Determines if an IGMP message should be sent for the
 *              specified multicast address.
 * Parameters:
 * Returns:     >=0 = success , <0 = error code.
 *
 */
IP_STATIC Ip_bool
ipnet_igmp_should_send_message(IP_CONST Ipnet_ip4_addr_entry *addr_entry)
{
    Ipnet_netif *netif = ipnet_ip4_addr_to_netif(addr_entry);

    ip_assert(IP_IN_CLASSD(addr_entry->ipaddr_n));

    if (IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_LOOPBACK))
        return IP_FALSE;

    /* RFC 3376, chapter 5
       ...
       The all-systems multicast address, 224.0.0.1, is handled as a
       special case.  On all systems -- that is all hosts and routers,
       including multicast routers -- reception of packets destined to
       the all-systems multicast address, from all sources, is
       permanently enabled on all interfaces on which multicast
       reception is supported.  No IGMP messages are ever sent
       regarding the all-systems multicast address.
       ...
    */

    return addr_entry->ipaddr_n != ip_htonl(IP_INADDR_ALLHOSTS_GROUP);
}


/*
 *===========================================================================
 *                    ipnet_igmp_report
 *===========================================================================
 * Description: Sends a host membership report for the multicast address.
 * Parameters:  addr_entry - The address entry for which the report should be
 *                           sent for.
 *              report_type - One of the IPNET_MCAST_REPORT_xxx constants.
 * Returns:
 *
 */
IP_STATIC void
ipnet_igmp_report(Ipnet_ip4_addr_entry *addr_entry, Ip_u8 report_type)
{
    Ipnet_icmp_param  icmp_param;
    int               mode;
    Ipnet_netif      *netif = ipnet_ip4_addr_to_netif(addr_entry);

    if (!ipnet_igmp_should_send_message(addr_entry))
        return;

    mode = ipnet_igmp_host_compatibility_mode(netif);

    ipcom_memset(&icmp_param, 0, sizeof(icmp_param));
    icmp_param.to = *(struct Ip_in_addr *) &addr_entry->ipaddr_n;

    switch (mode)
    {
#ifdef IPNET_USE_SOURCE_SPECIFIC_MCAST
    case IPNET_IGMPV3_MODE:
        icmp_param.type = IPNET_IGMP4_TYPE_V3_MEMBERSHIP_REPORT;
        /*
         * RFC 3376, chapter 4.2.14
         *
         * Version 3 Reports are sent with an IP destination address
         * of 224.0.0.22, to which all IGMPv3-capable multicast
         * routers listen.
         */
        (void)ipcom_inet_pton(IP_AF_INET, "224.0.0.22", &icmp_param.to);
        break;
#endif /* IPNET_USE_SOURCE_SPECIFIC_MCAST */
    case IPNET_IGMPV2_MODE:
        icmp_param.type = IPNET_IGMP4_TYPE_V2_MEMBERSHIP_REPORT;
        break;
    default:
        icmp_param.type = IPNET_IGMP4_TYPE_V1_MEMBERSHIP_REPORT;
        break;
    }

    addr_entry->mcast.report_type = report_type;
    icmp_param.ifindex  = netif->ipcom.ifindex;
    icmp_param.vr       = netif->vr_index;
    icmp_param.data.igmp_addr_entry = addr_entry;
    (void) ipnet_icmp4_send(&icmp_param, IP_TRUE);

    ipnet_mcast_report_finish(&addr_entry->mcast,
                              (Ipnet_timeout_handler) ipnet_igmp_report_filter_change,
                              addr_entry);
}


/*
 *===========================================================================
 *                    ipnet_igmp_send_host_leave_group
 *===========================================================================
 * Description: Sends a host membership report for the multicast address.
 * Parameters:  addr_entry - The multicast address the host removing.
 * Returns:
 *
 */
IP_STATIC void
ipnet_igmp_send_host_leave_group(Ipnet_ip4_addr_entry *addr_entry)
{
    Ipnet_icmp_param  icmp_param;
    struct Ip_in_addr allrtrs;
    int               mode;
    Ipnet_netif      *netif = ipnet_ip4_addr_to_netif(addr_entry);

    if (!ipnet_igmp_should_send_message(addr_entry))
        return;

    mode = ipnet_igmp_host_compatibility_mode(netif);

    if (mode == IPNET_IGMPV1_MODE)
        return;

    if (mode == IPNET_IGMPV2_MODE)
    {
        ipcom_memset(&icmp_param, 0, sizeof(icmp_param));
        allrtrs.s_addr = ip_htonl(IP_INADDR_ALLRTRS_GROUP);
        icmp_param.type     = IPNET_IGMP4_TYPE_V2_LEAVE_GROUP;
        icmp_param.to       = allrtrs;
        icmp_param.ifindex  = netif->ipcom.ifindex;
        icmp_param.vr       = netif->vr_index;
        icmp_param.data.igmp_addr_entry = addr_entry;
        (void) ipnet_icmp4_send(&icmp_param, IP_TRUE);
        return;
    }

    /* IGMPV3 mode */
    ipnet_mcast_clear(&addr_entry->mcast);
    ipnet_igmp_report(addr_entry, IPNET_MCAST_REPORT_FILTER_CHANGE);
}


#ifndef IPCOM_FORWARDER_NAE
/*
 *===========================================================================
 *                    ipnet_igmp_report_general_query
 *===========================================================================
 * Description: Sends a host membership report for the multicast address
 *              as a response to a general query.
 * Parameters:  addr_entry - The address entry for which the report should be
 *                           sent for.
 * Returns:
 *
 */
IP_STATIC void
ipnet_igmp_report_general_query(Ipnet_ip4_addr_entry *addr_entry)
{
    ipnet_igmp_report(addr_entry, IPNET_MCAST_REPORT_GENERAL_QUERY);
}


/*
 *===========================================================================
 *                    ipnet_igmp_report_specific_query
 *===========================================================================
 * Description: Sends a host membership report for the multicast address
 *              as a response to a specific query.
 * Parameters:  addr_entry - The address entry for which the report should be
 *                           sent for.
 * Returns:
 *
 */
IP_STATIC void
ipnet_igmp_report_specific_query(Ipnet_ip4_addr_entry *addr_entry)
{
    ipnet_igmp_report(addr_entry, IPNET_MCAST_REPORT_SPECIFIC_QUERY);
}
#endif


/*
 *===========================================================================
 *                    ipnet_igmp_report_filter_change
 *===========================================================================
 * Description: Sends a host membership report for the multicast address
 *              as a response to a filter change at the socket level.
 * Parameters:  addr_entry - The address entry for which the report should be
 *                           sent for.
 * Returns:
 *
 */
IP_STATIC void
ipnet_igmp_report_filter_change(Ipnet_ip4_addr_entry *addr_entry)
{
    Ipnet_netif *netif = ipnet_ip4_addr_to_netif(addr_entry);

    if (addr_entry->mcast.filter_change_resend_count
        == netif->igmp_robustness_variable)
    {
        ipnet_timeout_cancel(addr_entry->mcast.filter_change_tmo);
        --addr_entry->mcast.filter_change_resend_count;
    }
    ipnet_igmp_report(addr_entry, IPNET_MCAST_REPORT_FILTER_CHANGE);
}


/*
 *===========================================================================
 *                    ipnet_igmp_report_all
 *===========================================================================
 * Description: Sends a host membership report for each multicast address
 *              joined on the interface.
 * Parameters:  netif - The interface to report multicast addresses for.
 *              max_delay_msec - A response must be sent within
 *                               [0..max_delay_msec] milliseconds.
 * Returns:
 *
 */
#ifndef IPCOM_FORWARDER_NAE
IP_STATIC void
ipnet_igmp_report_all(Ipnet_netif *netif, Ip_u32 max_delay_msec)
{
    Ipnet_ip4_addr_entry *addr;

    for (addr = netif->inet4_addr_list; addr != IP_NULL; addr = addr->next)
        if (addr->type == IPNET_ADDR_TYPE_MULTICAST)
            ipnet_mcast_schedule_membership_report(&addr->mcast,
                                                   IP_FALSE,
                                                   max_delay_msec,
                                                   (Ipnet_timeout_handler)
                                                   ipnet_igmp_report_general_query,
                                                   addr);
}


/*
 *===========================================================================
 *                    ipnet_igmp_input
 *===========================================================================
 * Description: Handles received IGMP messages.
 * Parameters:  dst - destination cache matching this packet.
 *              pkt - The IGMP packet (pkt->start is the offset to the
 *              IGMP header), this function takes ownership of the packet.
 * Returns:     0 = success, <0 error code.
 *
 */
IP_STATIC void
ipnet_igmp_input(Ipnet_dst_cache *dst, Ipcom_pkt *pkt)
{
    Ip_u32                max_delay_msec;
    Ipnet_timeout       **ptmo;
    Ip_u32                group_n;
    Ip_bool               is_specific_query = IP_FALSE;
    Ipnet_ip4_addr_entry *addr_entry = IP_NULL;
    Ipnet_netif          *netif;
    unsigned              msg_len = (unsigned) ipcom_pkt_get_length(pkt);
    Ipnet_pkt_icmp       *igmp_hdr = ipcom_pkt_get_data(pkt, 0);
    Ipnet_pkt_ip         *ip_hdr = ipcom_pkt_get_iphdr(pkt);

    if (!ipnet_icmp_and_igmp_is_sane(pkt)
        || ip_hdr->ttl != 1)
    {
        /*
         * Wrong checksum, invalid packet length or TTL != 1. All
         * versions of IGMP requires that the TTL field is set to 1 to
         * avoid routing of such datagrams.
         */
        ipcom_pkt_free(pkt);
        return;
    }

    if (!ipnet_dst_do_on_stack_idx(ipnet_primary_instance_idx(),
                                   &dst->flow_spec,
                                   pkt,
                                   (Ipnet_dst_cache_rx_func)ipnet_igmp_input,
                                   ipnet_ip4_dst_cache_rx_ctor))
    {
        /*
         * The packet has been forwarded to the primary stack instance
         * for processing.
         */
        return;
    }

    netif = ipnet_if_indextonetif(dst->flow_spec.vr,
                                  dst->flow_spec.ingress_ifindex);

    switch (igmp_hdr->type)
    {
    case IPNET_IGMP4_TYPE_MEMBERSHIP_QUERY:
        if (msg_len != IPNET_IGMPV2_QUERY_SIZE
            && (msg_len < IPNET_IGMPV3_MIN_QUERY_SIZE
                || (msg_len < IPNET_IGMPV3_MIN_QUERY_SIZE
                    + ip_ntohs(igmp_hdr->data.igmp.number_of_sources) * sizeof(Ip_u32))))
            /* Not a valid IGMPv1, v2 or v3 query */
            break;

        group_n = IPNET_IP4_GET_IPADDR(igmp_hdr->data.igmp.multicast_addr);
        if (group_n != IP_INADDR_ANY)
        {
            if (IP_IN_CLASSD(group_n) == IP_FALSE)
                /* Invalid group */
                break;
            addr_entry = ipnet_ip4_get_addr_entry(group_n, dst->flow_spec.vr, netif);
        }

#ifdef IPNET_USE_SOURCE_SPECIFIC_MCAST
        if (msg_len == IPNET_IGMPV2_QUERY_SIZE)
#endif
        {
            netif->igmp_query_interval = IPNET_MCAST_DEFAULT_QUERY_INTERVAL;

            if (igmp_hdr->code == 0)
            {
                /* send by a IGMPv1 multicast router */
                max_delay_msec = 10 * 1000;
                ptmo = &netif->igmpv1_querier_present_tmo;
            }
            else
            {
                /* send by a IGMPv2 multicast router */
                max_delay_msec = (Ip_u32)igmp_hdr->code * 100u;
#ifdef IPNET_USE_SOURCE_SPECIFIC_MCAST
                ptmo = &netif->igmpv2_querier_present_tmo;
#else
                ptmo = IP_NULL;
#endif
            }

#ifndef IPNET_USE_SOURCE_SPECIFIC_MCAST
            if (ptmo != IP_NULL)
#endif
            {
                if (*ptmo == IP_NULL)
                    IPCOM_LOG2(INFO,
                               "IPv4: enter IGMPv%d compatibility mode on interface %s",
                               igmp_hdr->code ? 2 : 1,
                               netif->ipcom.name);
                else
                    ipnet_timeout_cancel(*ptmo);

                (void) ipnet_timeout_schedule(dst->net,
                                              ((1000u
                                                * (Ip_u32)netif->igmp_robustness_variable
                                                * (Ip_u32)netif->igmp_query_interval)
                                               + max_delay_msec),
                                              IP_NULL,
                                              IP_NULL,
                                              ptmo);
            }
        }
#ifdef IPNET_USE_SOURCE_SPECIFIC_MCAST
        else
        {
            Ipcom_set    *sources = IP_NULL;
            Ipnet_pkt_ip *iphdr = ipcom_pkt_get_iphdr(pkt);

            if (iphdr->tos != IPNET_IGMPV3_TOS)
                /*
                 * RFC 3376 states that all IGMPv3 messages must have
                 * the IP header TOS field set to 0xc0.
                 */
                break;

            /* IGMPv3 */
            if (addr_entry != IP_NULL)
            {
                if (addr_entry->mcast.specific_query_sources != IP_NULL)
                    /*  Source specific query already pending, append sources to this one */
                    sources = addr_entry->mcast.specific_query_sources;
                else
                {
                    sources = ipcom_set_new(sizeof(struct Ip_in_addr));
                    if (sources != IP_NULL)
                    {
                        sources->user = IPNET_MCAST_RECORD_TYPE_NOT_SET;
                        addr_entry->mcast.specific_query_sources = sources;
                    }
                }
            }

            if (sources != IP_NULL)
            {
                unsigned i;

                is_specific_query = IP_TRUE;

                if (igmp_hdr->data.igmp.number_of_sources == 0
                    || sources->user == IPNET_MCAST_RECORD_TYPE_IS_EXCLUDE)
                {
                out_of_mem:
                    sources->user = IPNET_MCAST_RECORD_TYPE_IS_EXCLUDE;
                    ipcom_set_remove_all(sources);
                }
                else
                {
                    sources->user = IPNET_MCAST_RECORD_TYPE_IS_INCLUDE;
                    for (i = 0; i < ip_ntohs(igmp_hdr->data.igmp.number_of_sources); i++)
                        if (ipcom_set_add(sources, &igmp_hdr->data.igmp.source_addr[i * 2]) == IPCOM_ERR_NO_MEMORY)
                            /* Send report for everything on this group */
                            goto out_of_mem;
                }
            }

            /*
             * The Max Resp Code field specifies the maximum time
             * allowed before sending a responding report.  The actual
             * time allowed, called the Max Resp Time, is represented
             * in units of 1/10 second
             */
            max_delay_msec = ipnet_mcast_time_to_msec(igmp_hdr->code) / 10;
            if(IP_NULL == netif)
            {
                IPCOM_LOG0(ERR, "ipnet_igmp_input: netif is NULL, break!");
                break;
            }

            netif->igmp_query_interval = (Ip_u16)ipnet_mcast_time_to_msec(igmp_hdr->data.igmp.qqic);
            if (netif->igmp_query_interval == 0)
                netif->igmp_query_interval = IPNET_MCAST_DEFAULT_QUERY_INTERVAL;
        }
#endif /* IPNET_USE_SOURCE_SPECIFIC_MCAST */

        if (max_delay_msec == 0)
            /*
             * RFC3376 does not directly say that this is invalid, but
             * it would result in "ack-implosion" that is specifically
             * mention as something not allowed
             */
            break;

        if (group_n == IP_INADDR_ANY)
            /*
             * Create a Host Membership Report message for each
             * multicast group joined on interface 'netif'
             */
            ipnet_igmp_report_all(netif, max_delay_msec);
        else if (addr_entry != IP_NULL)
            ipnet_mcast_schedule_membership_report(&addr_entry->mcast,
                                                   is_specific_query,
                                                   max_delay_msec,
                                                   (Ipnet_timeout_handler)
                                                   (is_specific_query
                                                    ? ipnet_igmp_report_specific_query
                                                    : ipnet_igmp_report_general_query),
                                                   addr_entry);
        break;
    default:
        break;
    }

    (void)ipnet_ip4_deliver_to_raw_sock(dst, pkt, IP_TRUE);
}
#endif /* !IPCOM_FORWARDER_NAE */



/*
 *===========================================================================
 *                    ipnet_ip4_deliver_to_raw_sock
 *===========================================================================
 * Description: Delivers a copy of the packet to all matching sockets.
 * Parameters:  dst - destination cache matching the packet.
 *              pkt - The packet.
 *              take_ownership_of_pkt - Set to IP_TRUE if the control of the
 *              packet lifetime should be taken care of by this function.
 * Returns:      0 = success
 *              <0 = error code.
 *
 */
#ifndef IPCOM_FORWARDER_NAE
IP_STATIC int
ipnet_ip4_deliver_to_raw_sock(Ipnet_dst_cache *dst,
                              Ipcom_pkt *pkt,
                              Ip_bool take_ownership_of_pkt)
{
    int                 org_start;
    int                 matching_sockets;
    const Ipnet_pkt_ip *iphdr;
#if defined(IPNET_DEBUG) || defined(IPNET_STATISTICS) || defined(IPNET_DEBUG)
    Ipnet_data         *net = ipnet_pkt_get_stack_instance(pkt);
#endif

    IPCOM_WV_MARKER_1 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_VERBOSE,
                       1, 5, IPCOM_WV_NETDEVENT_START,
                       ipnet_ip4_deliver_to_raw_sock,
                       IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
    IPNET_STATS(net, raw4_input++);

    /*
     * Raw packets must contain the IP header.
     */
    iphdr = ipcom_pkt_get_iphdr(pkt);
    org_start = pkt->start;
    pkt->start = pkt->ipstart;

    matching_sockets = ipnet_raw_input(pkt,
                                       take_ownership_of_pkt,
                                       iphdr->p,
                                       &dst->flow_spec.from,
                                       0,
                                       &dst->flow_spec.to,
                                       0,
                                       (Ipnet_sock_lookup_f) ipnet_sock_ip4_lookup);
    if (take_ownership_of_pkt == IP_FALSE)
        pkt->start = org_start;
    return matching_sockets > 0 ? 0 : IPNET_ERRNO(EPROTONOSUPPORT);
}
#endif /* IPCOM_FORWARDER_NAE */


/*
 *===========================================================================
 *                    ipnet_ip4_apply_ancillary_data
 *===========================================================================
 * Description: Applies ancillary data and sticky options to parameters
 *              of the outgoing packet.
 * Parameters:  sock - The socket used when sending the packet.
 *              msg - Message data (can be IP_NULL).
 *              flow_spec - flow specficiation for this transmission
 *              ip4_info - IPv4 layer information about this packet.
 *              pkt - packet that is about to be sent.
 * Returns:      0 = success
 *              <0 = error code.
 *
 */
IP_STATIC int
ipnet_ip4_apply_ancillary_data(Ipnet_socket *sock,
                               IP_CONST struct Ip_msghdr *msg,
                               Ipnet_flow_spec *flow_spec,
                               Ipnet_ip4_layer_info *ip4_info,
                               Ipcom_pkt *pkt)
{
    struct Ip_cmsghdr     *cmsg;
    struct Ip_in_pktinfo  *pktinfo = IP_NULL;
    struct Ip_sockaddr_in *nexthop = IP_NULL;

    if (msg != IP_NULL && msg->msg_controllen > 0)
    {
        /* Set extensions header specified to sendmsg() (this overrides any sticky options) */
        ip_assert(msg->msg_control != IP_NULL);
        for (cmsg = IP_CMSG_FIRSTHDR(msg);
             cmsg != IP_NULL;
             cmsg = IP_CMSG_NXTHDR(msg, cmsg))
        {
            if (cmsg->cmsg_level != IP_IPPROTO_IP)
                continue;

            switch (cmsg->cmsg_type)
            {
            case IP_IP_TOS:
                flow_spec->ds = (Ip_u8) (*(int *) IP_CMSG_DATA(cmsg));
                break;
            case IP_IP_TTL:
                ip4_info->ttl = (Ip_u8) (*(int *) IP_CMSG_DATA(cmsg));
                break;
            case IP_IP_ROUTER_ALERT:
                if (*(Ip_u8 *) IP_CMSG_DATA(cmsg))
                    IP_BIT_SET(ip4_info->flags, IPNET_IP4_OPF_ROUTER_ALERT);
                break;
            case IP_IP_DONTFRAG:
                if (*(Ip_u8 *) IP_CMSG_DATA(cmsg))
                    IP_BIT_SET(ip4_info->flags, IPNET_IP4_OPF_DONT_FRAG);
                break;
            case IP_IP_PKTINFO:
                pktinfo = IP_CMSG_DATA(cmsg);
                break;
            case IP_IP_NEXTHOP:
                nexthop = IP_CMSG_DATA(cmsg);
                break;
            case IP_IP_X_VRID:
                IPCOM_PKT_SET_VRID(pkt, *(Ip_u8*) IP_CMSG_DATA(cmsg));
                break;
            default:
                IPCOM_LOG1(DEBUG, "IPv4: unsupported ancillary data type (%d)",
                           cmsg->cmsg_type);
                return IPNET_ERRNO(EOPNOTSUPP);
            }
        }
    }

    if (pktinfo != IP_NULL)
    {
        struct Ip_in_addr *from;

        if (pktinfo->ipi_ifindex != 0)
        {
            Ipnet_netif *netifout;
            netifout = ipnet_if_indextonetif(sock->vr_index, pktinfo->ipi_ifindex);  
            if (IP_UNLIKELY(netifout == IP_NULL))
                return IPNET_ERRNO(ENXIO);

            if (ipnet_ip4_get_addr_type(IP_GET_32ON16(&flow_spec->to.in),
                                   netifout->vr_index,
                                   netifout) != IPNET_ADDR_TYPE_UNICAST)
                flow_spec->egress_ifindex = pktinfo->ipi_ifindex;

        }

#ifdef IP_PORT_LKM
        from = &pktinfo->ipi_spec_dest;
#else
        from = &pktinfo->ipi_addr;
#endif

        if (from->s_addr != IP_INADDR_ANY)
        {
            /* Check the interface addresses */
            if (ipnet_ip4_get_addr_type(from->s_addr, sock->vr_index, IP_NULL)
                != IPNET_ADDR_TYPE_UNICAST)
            {
                /* Invalid source address */
                return IPNET_ERRNO(EADDRNOTAVAIL);
            }
           flow_spec->from.in = *from;
        }
    }

    if (nexthop != IP_NULL)
    {
        Ipnet_netif *netif;

        if (flow_spec->egress_ifindex)
            netif = ipnet_if_indextonetif(flow_spec->vr,
                                          flow_spec->egress_ifindex);
        else
        {
            int                ret;
            Ipnet_route_entry *rt_next_hop;

            /*
             * Need to figure out the egress interface in order to get
             * the neighbor entry for the next hop
             */
            ipnet_route_lock();
            ret = ipnet_route_lookup_l(IP_AF_INET,
                                       sock->vr_index,
                                       IPCOM_ROUTE_TABLE_DEFAULT,
                                       0,
                                       &nexthop->sin_addr,
                                       0,
                                       flow_spec->egress_ifindex,
                                       &rt_next_hop);
            if (ret < 0)
            {
                ipnet_route_unlock();
                return ret;
            }

            netif = rt_next_hop->netif;
            ipnet_route_unlock();
        }

        if (netif == IP_NULL)
            return IPNET_ERRNO(ENXIO);

        /*
         * Get the neighbor, create if needed.
         */
        ip4_info->nexthop = ipnet_neigh_get(IP_AF_INET,
                                            &nexthop->sin_addr,
                                            netif,
                                            IPNET_NEIGH_CAN_CREATE);
        if (ip4_info->nexthop == IP_NULL)
            return IPNET_ERRNO(ENOMEM);
    }

    return 0;
}


/*
 *===========================================================================
 *                     ipnet_ip4_get_global_src_addr_ext
 *===========================================================================
 * Description: Returns a global address that is most resonable to use by default
 *              The actual address used can be changed by ipcom_bind().
 * Parameters:  vr - The virtual route table to use.
 *              dst_addr - The destination address
 *              filter - optional source address filter
 *              filter_arg - context argument for filter
 * Returns:     The 'best' match address or IP_NULL if no address was found
 *              that matches the criteria.
 *
 */
IP_STATIC IP_CONST struct Ip_in_addr *
ipnet_ip4_get_global_src_addr_ext(Ip_u16                      vr,
                                  IP_CONST struct Ip_in_addr *dst_addr,
                                  Ip_src_addr_filter          filter,
                                  void *                      filter_arg)
{
    Ip_u32                dst_n;
    Ipnet_ip4_addr_entry *addr;

    dst_n = IP_GET_32ON16((void *)dst_addr);
    if (!IP_IN_CLASSD(dst_n) && dst_n != IP_INADDR_BROADCAST && dst_n != IP_INADDR_ANY)
    {
        /* Check the global list */
        for (addr = ipnet_shared()->ip4.globals; addr != IP_NULL; addr = addr->global_next)
        {
            Ipnet_netif *netif = ipnet_ip4_addr_to_netif(addr);

            /* Don't bother with anything but Unicast */
            if (addr->type != IPNET_ADDR_TYPE_UNICAST)
                continue;

            if (IP_BIT_ISFALSE(addr->flags, IPNET_IP4_ADDR_FLAG_PREFERRED))
                continue;

            /* Must be one the correct VR */
            if (vr != netif->vr_index)
                continue;

            /* Must be up */
            if (IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_UP))
            {
                if (filter == IP_NULL ||
                    filter(&addr->ipaddr_n, IP_AF_INET, 0, filter_arg))
                    return (struct Ip_in_addr *) &addr->ipaddr_n;
            }
        }
    }

    return IP_NULL;
}



/*
 *===========================================================================
 *                      ipnet_ip4_remove_bcast_addr
 *===========================================================================
 * Description: Removes the network broadcast addresses associated with
 *              the specified unicast address.
 * Parameters:  addr - an unicast address
 * Returns:     0 = success, <0 = error code
 *
 */
IP_STATIC int
ipnet_ip4_remove_bcast_addr(Ipnet_ip4_addr_entry *addr)
{
    Ip_u32 netbrd_n;
    int    ret = 0;
    int    ret2;

    if (IP_BIT_ISSET(addr->flags, IPNET_IP4_ADDR_FLAG_NETBRD))
    {
        /*
         * Remove the old subnet broadcast address
         * new style broadcast {<network>,-1}
         */
        netbrd_n = (addr->ipaddr_n & addr->netmask_n) | ~addr->netmask_n;
        ret = ipnet_ip4_remove_addr(addr->netif, netbrd_n);

        /*
         * ...and old style {<network>,0}
         */
        netbrd_n &= addr->netmask_n;
        ret2 = ipnet_ip4_remove_addr(addr->netif, netbrd_n);

        ret = (ret ? ret : ret2);
        IP_BIT_CLR(addr->flags, IPNET_IP4_ADDR_FLAG_NETBRD);
    }

    return ret;
}



/*
 *===========================================================================
 *                          ipnet_ip4_with_sdl
 *===========================================================================
 * Description: Helper function that will call 'fn' in a context where
 *              global data might be written to.
 * Parameters:  fn - function to call, arguments are just forwarded to
 *                   this function
 * Returns:     Whatever 'fn' returns
 *
 */
IP_STATIC int
ipnet_ip4_with_sdl(Ipnet_netif *netif,
                   Ip_u32 ipaddr_n,
                   Ip_u32 netmask_n,
                   Ip_u16 flags,
                   enum Ipnet_addr_type addr_type,
                   int(*fn)(Ipnet_netif *, Ip_u32, Ip_u32, Ip_u16, enum Ipnet_addr_type))
{
    void *h_suspend = IP_NULL;
    int   ret;

    ip_assert(ipnet_primary_instance_idx() == ipnet_this());
    ip_assert(ipnet_shared()->fib.lock_owner != ipcom_getpid());

    if (!ipnet_can_update_shared_data())
        h_suspend = ipnet_suspend_stack();
    ret = fn(netif, ipaddr_n, netmask_n, flags, addr_type);
    if (h_suspend)
        ipnet_resume_stack(h_suspend);
    return ret;
}


/*
 *===========================================================================
 *                          ipnet_ip4_with_sdl2
 *===========================================================================
 * Description: Helper function that will call 'fn' in a context where
 *              global data might be written to.
 * Parameters:  fn - function to call, arguments are just forwarded to
 *                   this function
 * Returns:     Whatever 'fn' returns
 *
 */
IP_STATIC int
ipnet_ip4_with_sdl2(Ipnet_netif *netif,
                    Ip_u32 ipaddr_n,
                    int(*fn)(Ipnet_netif *, Ip_u32))
{
    return ipnet_ip4_with_sdl(netif, ipaddr_n, 0, 0, 0,
        (int(*)(Ipnet_netif *, Ip_u32, Ip_u32, Ip_u16, enum Ipnet_addr_type))fn);
}


/*
 ****************************************************************************
 * 10                   GLOBAL FUNCTIONS
 ****************************************************************************
 */


/*
 *===========================================================================
 *                    ipnet_ip4_insert_addr_cache
 *===========================================================================
 * Description: Adds an address to a set of hash tables to make it possible
 *              to find the entry in constant time for all types of addresses.
 * Parameters:  addr - The address entry to cache.
 * Returns:     0 = success
 *              -IP_ERRNO_ENOMEM = not enough memory
 *
 */
IP_GLOBAL int
ipnet_ip4_insert_addr_cache(Ipnet_ip4_addr_entry *addr)
{
    Ipnet_ip4_addr_lookup  l;
    Ipnet_ip4_addr_entry  *a;
    Ipnet_netif           *netif = ipnet_ip4_addr_to_netif(addr);
    Ipnet_ip4_shared_data *shrd_ip4 = &ipnet_shared()->ip4;

    IPNET_DEBUG_LINE(ip_assert(ipnet_can_update_shared_data()));

    l.ifindex     = netif->ipcom.ifindex;
    l.addr.s_addr = addr->ipaddr_n;
    l.vr          = netif->vr_index;

    ip_assert(ipcom_hash_get(shrd_ip4->addrs, &l) == IP_NULL);

    /* Direct match on interface, route table and address */
    if (ipcom_hash_add(shrd_ip4->addrs, addr) != IPCOM_SUCCESS)
        return IPNET_ERRNO(ENOMEM);

    if (addr->type != IPNET_ADDR_TYPE_UNICAST)
        return 0;

    /* Match on route table and address */
    a = ipcom_hash_get(shrd_ip4->addrs_ignore_if, &l);

    if (a == IP_NULL)
    {
        if (ipcom_hash_add(shrd_ip4->addrs_ignore_if, addr) != IPCOM_SUCCESS)
            return IPNET_ERRNO(ENOMEM);
    }
    else
    {
        addr->next_dup_addr = a->next_dup_addr;
        a->next_dup_addr = addr;
    }

    /**/
    if (IP_BIT_ISTRUE(addr->flags, IPNET_IP4_ADDR_FLAG_HOMEADDRESS))
    {
        addr->global_next   = shrd_ip4->globals;
        shrd_ip4->globals  = addr;
    }

    return 0;
}


/*
 *===========================================================================
 *                    ipnet_ip4_remove_addr_cache
 *===========================================================================
 * Description:
 * Parameters:  addr - The address entry to remove the cache for.
 * Returns:
 *
 */
IP_GLOBAL void
ipnet_ip4_remove_addr_cache(Ipnet_ip4_addr_entry *addr)
{
    Ipnet_ip4_addr_entry *a;
    Ipnet_ip4_addr_lookup l;
    Ipnet_netif          *netif = ipnet_ip4_addr_to_netif(addr);
    Ipnet_ip4_shared_data *shrd_ip4 = &ipnet_shared()->ip4;

    ip_assert(ipnet_can_update_shared_data());

    (void)ipcom_hash_remove(shrd_ip4->addrs, addr);

    if (addr->type != IPNET_ADDR_TYPE_UNICAST)
        return;

    /* Match on route table and address */
    l.ifindex     = netif->ipcom.ifindex;
    l.vr          = netif->vr_index;
    l.addr.s_addr = addr->ipaddr_n;
    a = ipcom_hash_get(shrd_ip4->addrs_ignore_if, &l);
    if (a != IP_NULL)
    {
        if (a == addr)
        {
            (void)ipcom_hash_remove(shrd_ip4->addrs_ignore_if, a);
            if (a->next_dup_addr != IP_NULL)
                (void)ipcom_hash_add(shrd_ip4->addrs_ignore_if, a->next_dup_addr);
        }
        else
        {
            while (a->next_dup_addr != addr)
                a = a->next_dup_addr;
            a->next_dup_addr = addr->next_dup_addr;
        }
        addr->next_dup_addr = IP_NULL;
    }

    /**/
    if (IP_BIT_ISTRUE(addr->flags, IPNET_IP4_ADDR_FLAG_HOMEADDRESS))
    {
        Ipnet_ip4_addr_entry **ap;

        /* Go through the globals */
        for (ap = &shrd_ip4->globals; *ap != IP_NULL; ap = &((*ap)->global_next))
        {
            /* Unlink it */
            if ((*ap) == addr)
            {
                *ap = addr->global_next;
                addr->global_next = IP_NULL;
                break;
            }
        }
    }
}


/*
 *===========================================================================
 *                    ipnet_ip4_remove_addr
 *===========================================================================
 * Description: Removed a address from a interface.
 * Parameters:  netif - The interface that has the address to remove.
 *              ipaddr_n - The address to remove.
 * Returns:     >=0 = success (value returned is the reference count), <0 = error code.
 *
 */
IP_GLOBAL int
ipnet_ip4_remove_addr(Ipnet_netif *netif, Ip_u32 ipaddr_n)
{
    Ipnet_ip4_addr_entry **addr_it;
    Ipnet_ip4_addr_entry  *del_addr = IP_NULL;
    int                    ret = 0;
    Ip_u16                 vr = netif->vr_index;

    if (!ipnet_can_update_shared_data())
        return ipnet_ip4_with_sdl2(netif, ipaddr_n, ipnet_ip4_remove_addr);

    for (addr_it = &netif->inet4_addr_list;
         *addr_it != IP_NULL;
         addr_it = &(*addr_it)->next)
    {
        if ((*addr_it)->ipaddr_n == ipaddr_n)
        {
            del_addr = *addr_it;
            break;
        }
    }

    if (del_addr == IP_NULL)
        /* No such address */
        return IPNET_ERRNO(EADDRNOTAVAIL);

    if (--del_addr->refcnt > 0)
        return 0;

    /* Cancel any running timer for this address */
    ipnet_timeout_cancel(del_addr->tmo);
#if defined(IPNET_USE_RFC3927) || defined(IPNET_USE_RFC5227)
    ipnet_timeout_cancel(del_addr->acd.tmo);
    if((IPNET_IP4_ACD_STATE_PROBE == del_addr->acd.state)
             && (del_addr->acd.num > 0)
             && (del_addr->type == IPNET_ADDR_TYPE_UNICAST))
        ipv4AddressEventHookProcess(IP_ADDREVENT_INET_DADABORTED, netif->ipcom.ifindex, 
                                             del_addr->ipaddr_n, (void *)&(netif->ipcom.link_addr));
#endif

    /* Remove the entry from the list */
    *addr_it = del_addr->next;

    if (del_addr->socket_list != IP_NULL)
    {
        Ipnet_ip4_addr_entry *addr_entry = IP_NULL;

        /*
         * Clients can bind to multicast addresses not joined by IPNET
         * since that some UNIX application expects that to be possible
         */
        ip_assert(del_addr->type != IPNET_ADDR_TYPE_MULTICAST);
        /* One or more sockets are bound to this address */
        if (del_addr->type == IPNET_ADDR_TYPE_UNICAST)
            addr_entry = del_addr->next_dup_addr;
        else
        {
            Ipnet_route_entry *rt;
            int                r;

            ipnet_route_lock();
            r = ipnet_route_lookup_l(IP_AF_INET,
                                     vr,
                                     IPCOM_ROUTE_TABLE_DEFAULT,
                                     0,
                                     &del_addr->ipaddr_n,
                                     0,
                                     0,
                                     &rt);
            while (r == IPNET_ROUTE_PERFECT_MATCH
                   && addr_entry == IP_NULL
                   && rt != IP_NULL)
            {
                addr_entry = ipnet_ip4_get_addr_entry(del_addr->ipaddr_n, vr, rt->netif);
                rt = rt->next;
            }
            ipnet_route_unlock();
        }

        if (addr_entry == IP_NULL)
            /* No other interface has this address assigned, notify all sockets */
            ipnet_sock_bind_addr_removed(del_addr->socket_list);
        else
            ipnet_sock_change_addr_entry(del_addr->socket_list, &addr_entry->socket_list, addr_entry);
    }

    if (IP_BIT_ISSET(del_addr->flags, IPNET_IP4_ADDR_FLAG_LOOPBACK_RT))
        (void) ipnet_route_delete2(IP_AF_INET,
                                   vr,
                                   IPCOM_ROUTE_TABLE_DEFAULT,
                                   &del_addr->ipaddr_n,
                                   IP_NULL,
                                   IP_NULL,
                                   netif->ipcom.type == IP_IFT_LOOP ? netif->ipcom.ifindex : 0,
                                   0,
                                   0,
                                   IP_TRUE);

    if (IP_BIT_ISSET(del_addr->flags, IPNET_IP4_ADDR_FLAG_HOST_RT))
        (void) ipnet_route_delete2(IP_AF_INET,
                                   vr,
                                   IPCOM_ROUTE_TABLE_DEFAULT,
                                   &del_addr->ipaddr_n,
                                   IP_NULL,
                                   IP_NULL,
                                   netif->ipcom.ifindex,
                                   0,
                                   0,
                                   IP_TRUE);

    if (IP_BIT_ISSET(del_addr->flags, IPNET_IP4_ADDR_FLAG_NETWORK_RT))
    {
        Ip_u32 netaddr_n;
        struct Ip_sockaddr_in        local_addr;

        netaddr_n = del_addr->ipaddr_n & del_addr->netmask_n;
        (void) ipnet_route_delete2(IP_AF_INET,
                                   vr,
                                   IPCOM_ROUTE_TABLE_DEFAULT,
                                   &netaddr_n,
                                   &del_addr->netmask_n,
                                   (del_addr->type == IPNET_ADDR_TYPE_UNICAST
                                    ? ipnet_ip4_addr_to_sockaddr(&local_addr, del_addr->ipaddr_n)
                                    : IP_NULL),
                                   netif->ipcom.ifindex,
                                   0,
                                   0,
                                   IP_TRUE);
    }

    if (del_addr->type == IPNET_ADDR_TYPE_UNICAST)
    {
        /*
         * Invalidate the route cache tag since assigning this address
         * might have affects on the outcome of lookups
         */
        ipnet_neigh_flush(IP_AF_INET,
                          netif,
                          &del_addr->ipaddr_n,
                          &del_addr->netmask_n);
        ipnet_neigh_flush(IP_AF_INET,
                          ipnet_loopback_get_netif(vr),
                          &del_addr->ipaddr_n,
                          IP_NULL);
    }

    if (del_addr->type == IPNET_ADDR_TYPE_UNICAST
        || del_addr->type == IPNET_ADDR_TYPE_MULTICAST)
        /*
         * Invalidate the route cache tag since assigning this address
         * might have affects on the outcome of lookups
         */
        ipnet_dst_cache_flush(vr, IP_AF_INET);

    ipnet_ip4_remove_addr_cache(del_addr);

    (void)ipnet_ip4_remove_bcast_addr(del_addr);

    if (del_addr->type == IPNET_ADDR_TYPE_UNICAST || del_addr->type == IPNET_ADDR_TYPE_MULTICAST)
    {
        ipnet_kioevent(netif, IP_EIOXDELADDR, IP_NULL, IP_FLAG_FC_STACKCONTEXT);
        IPNET_ROUTESOCK(ipnet_routesock_addr_delete(netif, IP_AF_INET, del_addr));
        IPNET_NETLINKSOCK(ipnet_rtnetlink_ip4_addr_del(netif, del_addr));
        IPCOM_LOG2(INFO, "IPv4: removed %s from %s",
                   ipcom_inet_ntop(IP_AF_INET, &ipaddr_n, ipnet_ptr()->log_buf,
                                   sizeof(ipnet_ptr()->log_buf)), netif->ipcom.name);
    }
    else
    {
        IPCOM_LOG2(DEBUG, "IPv4: removed %s from %s",
                   ipcom_inet_ntop(IP_AF_INET, &ipaddr_n, ipnet_ptr()->log_buf,
                                   sizeof(ipnet_ptr()->log_buf)), netif->ipcom.name);
    }

    if (del_addr->type == IPNET_ADDR_TYPE_MULTICAST)
    {
        if (del_addr->ipaddr_n != ip_htonl(IP_INADDR_ALLHOSTS_GROUP))
            ipnet_igmp_send_host_leave_group(del_addr);
        ipnet_mcast_free(&del_addr->mcast);
    }

    if (IP_BIT_ISSET(del_addr->flags, IPNET_IP4_ADDR_FLAG_MCAST))
        ret = ipnet_if_link_ioctl(netif,
                                  IP_SIOCXDELMULTI_IN,
                                  (void*) &ipaddr_n);

#ifdef IPNET_USE_RFC3927
    if((del_addr->type == IPNET_ADDR_TYPE_UNICAST)
        && (!IP_BIT_ISSET(del_addr->flags, IPNET_IP4_ADDR_FLAG_LINK_LOCAL))
        && (netif->eth != IP_NULL)
        && (IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_UP))
        && (!IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_LOOPBACK))
        && (ipnet_ip4_lladdr_isenabled(netif) == IP_TRUE)
        && (ipnet_ip4_has_routeable_addr(netif) == IP_FALSE)
        && (ipnet_ip4_has_link_local_addr(netif) == IP_FALSE))
    {
        /*
         * RFC 3927, chapter 1.9
         * 3. If a host finds that an interface no longer has an operable
         * routable address available, the host MAY identify a usable IPv4
         * Link-Local address (as described in section 2) and assign that
         * address to the interface.
         */
        IPCOM_LOG1(INFO, "IPv4: No routable address on %s. Adding new link local address",
                                   netif->ipcom.name);

        ipnet_ip4_lladdr_add(netif);
    }
#endif /* IPNET_USE_RFC3927 */

    if (del_addr->neigh)
    {
        /*
         * Remove the public neighbor entry used to answer to ARP
         * solicitations on this address.
         */
        ipcom_observer_remove(&del_addr->neigh->observers,
                              &del_addr->neigh_observer);
        ipnet_neigh_set_state(del_addr->neigh, IPNET_ND_DEAD);
        ipnet_neigh_release(del_addr->neigh);
    }
    ipcom_slab_free(ipnet_shared()->ip4.addr_slab, del_addr);
    return ret;
}


/*
 *===========================================================================
 *                    ipnet_ip4_change_addr_mask
 *===========================================================================
 * Description: Changes the mask for an existing addres.
 * Parameters:  addr - the address entry to change the mask for.
 *              new_netmask_n - The new mask.
 * Returns:     0 = success, <0 = error code.
 *
 */
IP_GLOBAL int
ipnet_ip4_change_addr_mask(Ipnet_ip4_addr_entry *addr, Ip_u32 new_netmask_n)
{
    Ipnet_netif *netif;
    int          ret;

    if (addr->type != IPNET_ADDR_TYPE_UNICAST)
        /* Network mask is not used */
        return 0;

    if (addr->netmask_n == new_netmask_n)
        /* Mask is already correct */
        return 0;

    if (new_netmask_n != 0 && (new_netmask_n & ip_htonl(0xff000000)) == 0)
    {
        /* The mask did not pass basic sanity checks */
        return IPNET_ERRNO(EINVAL);
    }

    if (ip_ntohl(new_netmask_n) < 0xfffffffe)
    {
        if ((addr->ipaddr_n & ~new_netmask_n) == 0)
            /*
             * Unicast address equal to the old style network
             * broadcast
             */
            return IPNET_ERRNO(EINVAL);

        if ((addr->ipaddr_n & ~new_netmask_n) == ~new_netmask_n)
            /*
             * Unicast address equal to the new style network
             * broadcast
             */
            return IPNET_ERRNO(EINVAL);
    }
    /*
     * else:
     * Networks with prefix /32 (single host) and /31 (two hosts as
     * defined by RFC3021) does not have network broadcast addresses
     */

    ret = 0;
    netif = ipnet_ip4_addr_to_netif(addr);

    if (IP_BIT_ISSET(addr->flags, IPNET_IP4_ADDR_FLAG_NETWORK_RT))
    {
        struct Ipnet_route_add_param param;
        Ip_u32                       netaddr_n;
        struct Ip_sockaddr_in        local_addr;

        if (new_netmask_n != 0xffffffff)
        {
            /* Add the new network interface route */
            ipcom_memset(&param, 0, sizeof(struct Ipnet_route_add_param));
            param.domain  = IP_AF_INET;
            param.vr      = netif->vr_index;
            param.table   = IPCOM_ROUTE_TABLE_DEFAULT;
            param.netif   = netif;
            netaddr_n     = addr->ipaddr_n & new_netmask_n;
            param.key     = &netaddr_n;
            param.netmask = &new_netmask_n;
            param.flags   = IPNET_RTF_UP | IPNET_RTF_DONE
                | IPNET_RTF_MASK | IPNET_RTF_CLONING;
            if (addr->type == IPNET_ADDR_TYPE_UNICAST)
                /*
                 * The gateway field will is the default source
                 * address for packets sent to the network for this
                 * address
                 */
                param.gateway = ipnet_ip4_addr_to_sockaddr(&local_addr, addr->ipaddr_n);
            ret = ipnet_route_add(&param);
            if (ret < 0)
                return ret;
        }


        /* Remove the old */
        netaddr_n = addr->ipaddr_n & addr->netmask_n;
        (void) ipnet_route_delete2(IP_AF_INET,
                                   netif->vr_index,
                                   IPCOM_ROUTE_TABLE_DEFAULT,
                                   &netaddr_n,
                                   &addr->netmask_n,
                                   addr->type == IPNET_ADDR_TYPE_UNICAST? ipnet_ip4_addr_to_sockaddr(&local_addr, addr->ipaddr_n) : IP_NULL,
                                   netif->ipcom.ifindex,
                                   0,
                                   0,
                                   IP_TRUE);
    }

    if (IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_BROADCAST))
    {
        /* Change the subnet broadcast address */
        ret = ipnet_ip4_remove_bcast_addr(addr);

        if (ret >= 0
            && ip_ntohl(new_netmask_n) < 0xfffffffe)
        {
            Ip_u32 netbrd_n;
            int    ret2;

            /*
             * New style network broadcast {<network>,-1}
             */
            netbrd_n = (new_netmask_n & addr->ipaddr_n) | ~new_netmask_n;
            if (netbrd_n == addr->ipaddr_n)
                ret = IPNET_ERRNO(EINVAL);
            else
                ret = ipnet_ip4_add_addr(netif,
                                         netbrd_n,
                                         0,
                                         IP_FALSE,
                                         IPNET_ADDR_TYPE_NETBROADCAST);

            /*
             * Old style network broadcast {<network>,0}
             */
            netbrd_n &= new_netmask_n;
            if (netbrd_n == addr->ipaddr_n)
                ret2 = IPNET_ERRNO(EINVAL);
            else
                ret2 = ipnet_ip4_add_addr(netif,
                                          netbrd_n,
                                          0,
                                          IP_FALSE,
                                          IPNET_ADDR_TYPE_NETBROADCAST);


            ret = (ret ? ret : ret2);
            IP_BIT_SET(addr->flags, IPNET_IP4_ADDR_FLAG_NETBRD);
        }
    }

    if (ret >= 0)
        addr->netmask_n = new_netmask_n;

    return ret;
}


/*
 *===========================================================================
 *                    ipnet_ip4_add_addr
 *===========================================================================
 * Description: Adds an address to an interface.
 * Parameters:  netif - The interface to which the address should be assigned.
 *              ipaddr_n - The address to assign.
 *              netmask_n - The netmask for the address.
 *              primary - Set to IP_TRUE if this address is the new primary address.
 *              addr_type - One of the IPNET_ADDR_TYPE_xxx constants.
 * Returns:     0 = success (value is address ref. count), <0 = error code.
 *
 */
IP_GLOBAL int
ipnet_ip4_add_addr(Ipnet_netif *netif, Ip_u32 ipaddr_n, Ip_u32 netmask_n,
                   Ip_bool primary, enum Ipnet_addr_type addr_type)
{
    return ipnet_ip4_add_addr2(netif,
                               ipaddr_n,
                               netmask_n,
                               (Ip_u16)(primary ? IPNET_IP4_ADDR_FLAG_PRIMARY : 0),
                               addr_type);
}


/*
 *===========================================================================
 *                       ipnet_ip4_netif_get_subbrd
 *===========================================================================
 * Description: Gets broadcast address of netif
 * Parameters:  netif - The interface to which the address should be
 *                    assigned.
 * Returns:     subnet broadcast address or 0
 *
 */
IP_GLOBAL Ip_u32
ipnet_ip4_netif_get_subbrd(Ipnet_netif *netif)
{

    Ipnet_ip4_addr_entry **plast_addr = &netif->inet4_addr_list;
    Ipnet_ip4_addr_entry  *addr;
    Ip_u32                 subbrd_n=0;

    /*
     * Add it after all unicast address(es), any link local IPv4 will
     * always be the last unicast address
     */

    addr = netif->inet4_addr_list;
    if (addr != IP_NULL && addr->type != IPNET_ADDR_TYPE_UNICAST)
        addr = IP_NULL;
    if(addr != IP_NULL)
        subbrd_n  = (addr->ipaddr_n & addr->netmask_n) | ~addr->netmask_n;  /* Old code 1 line */

    while (*plast_addr != IP_NULL
           && ((*plast_addr)->type != IPNET_ADDR_TYPE_NETBROADCAST || ((*plast_addr)->ipaddr_n == subbrd_n)))
            plast_addr = &(*plast_addr)->next;

    /* There was a subnet broadcast address found */
    if(*plast_addr != IP_NULL
       && (*plast_addr)->type == IPNET_ADDR_TYPE_NETBROADCAST
       && (*plast_addr)->ipaddr_n != subbrd_n )
        return (*plast_addr)->ipaddr_n;

    return 0;

}


/*
 *===========================================================================
 *                    ipnet_ip4_add_addr2
 *===========================================================================
 * Description: Adds an address to an interface.
 * Parameters:  netif - The interface to which the address should be assigned.
 *              ipaddr_n - The address to assign.
 *              netmask_n - The netmask for the address.
 *              flags - IPNET_IP4_ADDR_FLAG_xxx flags that is read/writable.
 *              addr_type - One of the IPNET_ADDR_TYPE_xxx constants.
 * Returns:     0 = success (value is address ref. count), <0 = error code.
 *
 */
IP_GLOBAL int
ipnet_ip4_add_addr2(Ipnet_netif *netif,
                    Ip_u32 ipaddr_n,
                    Ip_u32 netmask_n,
                    Ip_u16 flags,
                    enum Ipnet_addr_type addr_type)
{
    Ipnet_ip4_addr_entry *addr;
    int                   ret = 0;

    if (!ipnet_can_update_shared_data())
        return ipnet_ip4_with_sdl(netif, ipaddr_n, netmask_n, flags, addr_type,
                                  ipnet_ip4_add_addr2);

    if (IP_BIT_ISSET(netif->flags2, IPNET_IFF2_NO_IPV4_SUPPORT))
        return IPNET_ERRNO(EPFNOSUPPORT);

    if (netmask_n == 0)
        /*
         * No mask specified, used the old class based netmask:s as
         * default
         */
        netmask_n = IP_NETMASK(ipaddr_n);

    addr = ipnet_ip4_get_addr_entry(ipaddr_n, netif->vr_index, netif);
    if (addr != IP_NULL)
    {
        /* Address exist already */
        if (addr->type == IPNET_ADDR_TYPE_MULTICAST
            || addr->type == IPNET_ADDR_TYPE_NETBROADCAST)
                /* Reference count multicast addresses */
            addr->refcnt++;

#if defined(IPTCP) && !defined(IPCOM_FORWARDER_NAE)
        if (IP_BIT_ISSET(addr->flags, IPNET_IP4_ADDR_FLAG_HOMEADDRESS))
        {
            Ipnet_socket *sock = addr->socket_list;
            Ipnet_socket *next_sock;

            while (sock != IP_NULL)
            {
                /* Locate next socket with the same address */
                next_sock = sock->addr_next;

                /* Do we have a notify CB */
                if (sock->notify_cb != IP_NULL)
                {
                    /* Kickstart it */
                    (*sock->notify_cb) (sock, IPTCP_SOCKET_EVENT_KICKSTART);
                }

                /* Do next socket */
                sock = next_sock;
            }
        }
 #endif /* IPTCP */

        return ipnet_ip4_change_addr_mask(addr, netmask_n);
    }

    addr = ipcom_slab_alloc(ipnet_shared()->ip4.addr_slab);
    if (addr == IP_NULL)
        return IPNET_ERRNO(ENOMEM);

    /* Initialize the address entry */
#ifdef IPCOM_USE_INET6
    addr->ipv6_mapped_space[2] = ip_htonl(0xffff);
#endif /* IPCOM_USE_INET6 */
    addr->netif     = netif;
    addr->ipaddr_n  = ipaddr_n;
    addr->type      = addr_type;
    addr->refcnt    = 1;
    addr->flags     = (Ip_u16)(IPNET_IP4_ADDR_FLAG_RW_MASK & flags);

    if (IP_BIT_ISSET(flags, IPNET_IP4_ADDR_FLAG_PRIMARY))
    {
        addr->next = netif->inet4_addr_list;
        netif->inet4_addr_list = addr;
    }
    else
    {
        Ipnet_ip4_addr_entry **plast_addr = &netif->inet4_addr_list;

        /*
         * Add it after all unicast address(es), any link local IPv4
         * will always be the last unicast address
         */
        while (*plast_addr != IP_NULL
               && (*plast_addr)->type == IPNET_ADDR_TYPE_UNICAST
               && (addr_type != IPNET_ADDR_TYPE_UNICAST
                   || IP_BIT_ISFALSE((*plast_addr)->flags, IPNET_IP4_ADDR_FLAG_LINK_LOCAL)))
            plast_addr = &(*plast_addr)->next;
        addr->next = *plast_addr;
        *plast_addr = addr;
    }

    switch (addr_type)
    {
    case IPNET_ADDR_TYPE_MULTICAST:
        /*
         * Join the multicast link address for this address
         */
#ifdef IPNET_USE_SOURCE_SPECIFIC_MCAST
        if ((ret = ipnet_mcast_init(&addr->mcast)) != 0)
            goto cleanup;
#endif

        ret = ipnet_if_link_ioctl(netif, IP_SIOCXADDMULTI_IN, &ipaddr_n);
        if (ret >= 0)
            IP_BIT_SET(addr->flags, IPNET_IP4_ADDR_FLAG_MCAST);
        addr->netmask_n = IP_IN_CLASSD_NET;
        break;

    case IPNET_ADDR_TYPE_UNICAST:
#if defined(IPNET_USE_RFC5227) || defined(IPNET_USE_RFC3927)
        /*
         * All addresses are tentative until address conflict
         * detection has completed
         */
        if ((netif->eth != IP_NULL)
            && (!IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_LOOPBACK))
#ifndef IPNET_USE_RFC5227
        /*
         * Only dynamic link-local address is tentative until address
         * conflict detection has completed
         */
            && (IP_BIT_ARESET(addr->flags, IPNET_IP4_ADDR_FLAG_LINK_LOCAL | IPNET_IP4_ADDR_FLAG_AUTOMATIC))
#else
        /*
         * Link local are always tentative.  Routable addresses are
         * tentative if sysvar is enabled
         */
            && (((netif->conf.inet.address_conflict_detect == IP_TRUE)
                 && (IP_BIT_ISFALSE(addr->flags, IPNET_IP4_ADDR_FLAG_LINK_LOCAL)))
                || (IP_BIT_ARESET(addr->flags, IPNET_IP4_ADDR_FLAG_LINK_LOCAL | IPNET_IP4_ADDR_FLAG_AUTOMATIC)))
#endif /* IPNET_USE_RFC5227*/
            )
        {
            IP_BIT_SET(addr->flags, IPNET_IP4_ADDR_FLAG_TENTATIVE);
        }
#endif /* #if defined(IPNET_USE_RFC5227) || defined(IPNET_USE_RFC3927) */

        ret = ipnet_ip4_change_addr_mask(addr, netmask_n);
        ipnet_neigh_flush(IP_AF_INET, netif, &addr->ipaddr_n, &addr->netmask_n);
        break;

    case IPNET_ADDR_TYPE_NETBROADCAST:
        addr->netmask_n = ~0u;
        break;

    default:
        IP_PANIC2();
        ret = IPNET_ERRNO(EINVAL);
        goto cleanup;
    }

    if (ret >= 0)
        ret = ipnet_ip4_insert_addr_cache(addr);

    if (ret < 0)
        goto cleanup;

    if (addr_type == IPNET_ADDR_TYPE_UNICAST || addr_type == IPNET_ADDR_TYPE_MULTICAST)
    {
        IPCOM_LOG2(INFO, "IPv4: added %s to %s",
                   ipcom_inet_ntop(IP_AF_INET, &ipaddr_n, ipnet_ptr()->log_buf, sizeof(ipnet_ptr()->log_buf)),
                   netif->ipcom.name);
    }
    else
    {
        IPCOM_LOG2(DEBUG, "IPv4: added %s to %s",
                   ipcom_inet_ntop(IP_AF_INET, &ipaddr_n, ipnet_ptr()->log_buf, sizeof(ipnet_ptr()->log_buf)),
                   netif->ipcom.name);
    }

    if (IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_UP))
    {
#if defined(IPNET_USE_RFC3927) || defined(IPNET_USE_RFC5227)
        if(IP_BIT_ISSET(addr->flags, IPNET_IP4_ADDR_FLAG_TENTATIVE))
        {
            ipnet_ip4_acd_set_state(addr, IPNET_IP4_ACD_STATE_INIT);
        }
        else
#endif /* #if defined(IPNET_USE_RFC3927) || defined(IPNET_USE_RFC5227) */
            return ipnet_ip4_assign_addr(addr);
    /* else: adding routes will be done when the interface is set UP */
    }
    return 0;

 cleanup:
    (void) ipnet_ip4_remove_addr(netif, ipaddr_n);
    return ret;

}


/*
 *===========================================================================
 *                    ipnet_ip4_kioevent
 *===========================================================================
 * Description: IPv4 handler for IO events on network interfaces.
 * Parameters:  netif - The network interface the event happened on.
 *              event - The event.
 * Returns:
 *
 */
IP_GLOBAL void
ipnet_ip4_kioevent(Ipnet_netif *netif, int event)
{
    Ipnet_ip4_addr_entry *addr;

    switch (event)
    {
    case IP_EIOXUP:
    case IP_EIOXRUNNING:
        if (IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_UP))
        {
            netif->igmp_robustness_variable = IPNET_MCAST_DEFAULT_ROBUSTNESS_VARIABLE;
            netif->igmp_query_interval = IPNET_MCAST_DEFAULT_QUERY_INTERVAL;

            for (addr = netif->inet4_addr_list; addr != IP_NULL; addr = addr->next)
            {
#if defined(IPNET_USE_RFC5227) || defined(IPNET_USE_RFC3927)
                if((netif->eth != IP_NULL)
                    && (!IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_LOOPBACK))
                    && (addr->type == IPNET_ADDR_TYPE_UNICAST)
#ifndef IPNET_USE_RFC5227
                /* Only dynamic link-local address is tentative untill address conflict detection has completed */
                   && (IP_BIT_ARESET(addr->flags, IPNET_IP4_ADDR_FLAG_LINK_LOCAL | IPNET_IP4_ADDR_FLAG_AUTOMATIC))
#else
                /* Link local are always tentative.
                 * Routable addresses are tentative if sysvar is enabled */
                   && (((netif->conf.inet.address_conflict_detect == IP_TRUE)
                        && (IP_BIT_ISFALSE(addr->flags, IPNET_IP4_ADDR_FLAG_LINK_LOCAL)))
                      || (IP_BIT_ARESET(addr->flags, IPNET_IP4_ADDR_FLAG_LINK_LOCAL | IPNET_IP4_ADDR_FLAG_AUTOMATIC)))
#endif /* #ifndef IPNET_USE_RFC5227 */
                )
                {
                    IP_BIT_SET(addr->flags, IPNET_IP4_ADDR_FLAG_TENTATIVE);
                    ipnet_ip4_acd_set_state(addr, IPNET_IP4_ACD_STATE_INIT);
                }
                else
#endif /* #if defined(IPNET_USE_RFC5227) || defined(IPNET_USE_RFC3927)  */
                {
                    if (ipnet_ip4_assign_addr(addr) < 0)
                        /* Start over since the current address has has been removed */
                        addr = netif->inet4_addr_list;
                }
            }
            if (event == IP_EIOXUP)
                ipnet_ip4_if_configure(netif);
#ifdef IPNET_USE_RFC1256
            else
                (void)ipnet_ip4_rfc1256_state_change(netif, IPNET_RFC1256_GENERIC_STATE_INITIALIZING);
#endif
        }
        break;
    case IP_EIOXDOWN:
        ipnet_ip4_if_unconfigure(netif);
        (void)ipnet_route_remove_all(IP_AF_INET, netif);
        for (addr = netif->inet4_addr_list; addr != IP_NULL; addr = addr->next)
        {
            if (IP_BIT_ISSET(addr->flags, IPNET_IP4_ADDR_FLAG_LOOPBACK_RT))
                (void) ipnet_route_delete2(IP_AF_INET,
                                           netif->vr_index,
                                           IPCOM_ROUTE_TABLE_DEFAULT,
                                           &addr->ipaddr_n,
                                           IP_NULL,
                                           IP_NULL,
                                           netif->ipcom.type == IP_IFT_LOOP ? netif->ipcom.ifindex : 0,
                                           0,
                                           0,
                                           IP_TRUE);
            /*
             * Clear this bits since all routes to this interface has
             * been removed
             */
            IP_BIT_CLR(addr->flags, IPNET_IP4_ADDR_FLAG_NETWORK_RT | IPNET_IP4_ADDR_FLAG_LOOPBACK_RT);

            ipnet_timeout_cancel(addr->tmo);
        }

        ipnet_neigh_flush(IP_AF_INET, netif, IP_NULL, IP_NULL);
        break;
    case IP_EIOXSTOP:
        /*
         * This will affect routing, flush the dst cache
         */
        ipnet_dst_cache_flush(netif->vr_index, IP_AF_INET);
        ipnet_neigh_flush(IP_AF_INET, netif, IP_NULL, IP_NULL);
#if defined(IPNET_USE_RFC5227) || defined(IPNET_USE_RFC3927)
        for (addr = netif->inet4_addr_list; addr != IP_NULL; addr = addr->next)
        {

            if((netif->eth != IP_NULL)
                && (!IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_LOOPBACK))
                && (addr->type == IPNET_ADDR_TYPE_UNICAST)
#ifndef IPNET_USE_RFC5227
               && (IP_BIT_ARESET(addr->flags, IPNET_IP4_ADDR_FLAG_LINK_LOCAL | IPNET_IP4_ADDR_FLAG_AUTOMATIC))
#else

               && (((netif->conf.inet.address_conflict_detect == IP_TRUE)
                    && (IP_BIT_ISFALSE(addr->flags, IPNET_IP4_ADDR_FLAG_LINK_LOCAL)))
                  || (IP_BIT_ARESET(addr->flags, IPNET_IP4_ADDR_FLAG_LINK_LOCAL | IPNET_IP4_ADDR_FLAG_AUTOMATIC)))
#endif /* #ifndef IPNET_USE_RFC5227 */
            )
            {
                ipnet_ip4_acd_set_state(addr, IPNET_IP4_ACD_STATE_DISABLED);
            }

        }
#endif

#ifdef IPNET_USE_RFC1256
        (void)ipnet_ip4_rfc1256_state_change(netif, IPNET_RFC1256_GENERIC_STATE_INITIALIZING);
#endif
        break;
    default:
        break;
    }
}


/*
 *===========================================================================
 *                    ipnet_ip4_get_src_addr
 *===========================================================================
 * Description: Returns the address that is most resonable to use by default
 *              for a route.
 *              The actual address used can be changed by ipcom_bind().
 * Parameters:  vr - The virtual route table to use.
 *              dst_addr - The destination addres
 *              rt - The route for 'dst_addr' or IP_NULL if this is not known.
 *              netif - The interface that MUST be used regardless of what
 *                      the route table says or IP_NULL if this should be
 *                      extracted from the route table.
 *              filter - optional address filter function
 *              filter_arg - context argument for filter function
 * Returns:     The 'best' match address or IP_NULL if no address was found
 *              that matches the criteria.
 *
 */
IP_STATIC IP_CONST struct Ip_in_addr *
ipnet_ip4_get_src_addr_rtl(Ip_u16                       vr,
                           IP_CONST struct Ip_in_addr   *dst_addr,
                           Ipnet_route_entry            *rt,
                           Ipnet_netif                  *netif,
                           Ip_src_addr_filter           filter,
                           void *                       filter_arg)
{
    Ip_u32                      dst_n;
    Ipnet_ip4_addr_entry       *addr;
    IP_CONST struct Ip_in_addr *selected_addr;
    Ipnet_netif                *cnetif  = netif;
    Ipnet_flow_spec             flow_spec;

    (void)ipnet_flow_spec_from_info(&flow_spec,
                              vr,
                              IP_NULL, dst_addr,
                              0, 0,
                              IP_NULL, netif,
                              ipnet_ip4_flow_spec_from_info);
    if (rt == IP_NULL)
    {
        if (ipnet_route_lookup_ecmp_l(IP_AF_INET,
                                      vr,
                                      0,
                                      dst_addr,
                                      0,
                                      0,
                                      IP_NULL,
                                      &flow_spec,
                                      &rt) < 0)
        {
            if (IP_UNLIKELY(ipnet_shared()->ip4.globals != IP_NULL) && netif == IP_NULL)
                return ipnet_ip4_get_global_src_addr_ext(vr, dst_addr, filter, filter_arg);
            return IP_NULL;
        }

        rt = ipnet_dst_cache_select_best_rt(IP_AF_INET, &flow_spec, rt);
    }

    if (cnetif == IP_NULL)
        cnetif = rt->netif;

    if (IP_BIT_ISSET(rt->hdr.flags, IPNET_RTF_GATEWAY)
        && ipnet_route_lookup_ecmp_l(IP_AF_INET,
                                     vr,
                                     IPNET_RTL_FLAG_DONTCLONE,
                                     &((struct Ip_sockaddr_in *) rt->gateway)->sin_addr,
                                     0,
                                     0,
                                     IP_NULL,
                                     &flow_spec,
                                     &rt) < 0)
        rt = IP_NULL;

    /*
     * If no network interface was explicitly specified, check the
     * globals; unless destination is LOOPBACK
     */
    if (netif == IP_NULL
        && (cnetif == IP_NULL
            || (IP_BIT_ISFALSE(cnetif->ipcom.flags, IP_IFF_LOOPBACK)
                && IP_BIT_ISFALSE(cnetif->flags2, IPNET_IFF2_NO_GLOBAL_SRC))))
    {
        /* Check the global list */
        for (addr = ipnet_shared()->ip4.globals;
             addr != IP_NULL;
             addr = addr->global_next)
        {
            Ipnet_netif *this_netif;

            /* Don't bother with anything but Unicast */
            if (addr->type != IPNET_ADDR_TYPE_UNICAST)
                continue;

            if (IP_BIT_ISFALSE(addr->flags, IPNET_IP4_ADDR_FLAG_PREFERRED))
                continue;

            /* Must be up */
            this_netif = ipnet_ip4_addr_to_netif(addr);
            if (IP_BIT_ISSET(this_netif->ipcom.flags, IP_IFF_UP)
#ifdef IPNET_USE_RFC5227
                /* Should not use a tentative address */
                && (!IP_BIT_ISSET(addr->flags, IPNET_IP4_ADDR_FLAG_TENTATIVE))
#endif
            )
            {
                if (filter == IP_NULL ||
                    filter(&addr->ipaddr_n, IP_AF_INET, 0, filter_arg))
                    return (struct Ip_in_addr *) &addr->ipaddr_n;
            }
        }
    }

    if (rt != IP_NULL
        && (netif == IP_NULL || netif == rt->netif))
    {
        if (rt->rt_template)
            rt = rt->rt_template;

        if (rt->gateway != IP_NULL
            && rt->gateway->sa_family == IP_AF_INET
            && IP_BIT_ISFALSE(rt->hdr.flags,
                              IPNET_RTF_TUNNELEND | IPNET_RTF_GATEWAY))
        {
            struct Ip_sockaddr_in *sin = (struct Ip_sockaddr_in *) rt->gateway;
            /*
             * The default source address was specified in the route
             * entry
             */
            if (filter == IP_NULL ||
                filter(&sin->sin_addr, IP_AF_INET, 0, filter_arg))
                return &sin->sin_addr;
        }
    }

    dst_n = IP_GET_32ON16((void *)dst_addr);
    if (!IP_IN_CLASSD(dst_n) && dst_n != IP_INADDR_BROADCAST && dst_n != IP_INADDR_ANY)
    {
        if (cnetif != IP_NULL && IP_BIT_ISSET(cnetif->ipcom.flags, IP_IFF_LOOPBACK))
        {
            Ipnet_netif *this_netif;
            Ip_u32       i;

            /* coverity[result_independent_of_operands] */
            IPNET_NETIF_FOR_EACH_ON_VR(this_netif, vr, i)
            {
                /*
                 * The dst_addr might be one of the addresses on one
                 * of the local interface, so all interfaces is
                 * searched for a perfect address match
                 */
                for (addr = this_netif->inet4_addr_list; addr != IP_NULL; addr = addr->next)
                {
                    if ((addr->ipaddr_n == dst_n)
#ifdef IPNET_USE_RFC5227
                        /* Should not use a tentative address */
                        && (!IP_BIT_ISSET(addr->flags, IPNET_IP4_ADDR_FLAG_TENTATIVE))
#endif
                        )
                    {
                        if (filter == IP_NULL ||
                            filter(&addr->ipaddr_n, IP_AF_INET, 0, filter_arg))
                            return (struct Ip_in_addr *) &addr->ipaddr_n;
                    }
                }
            }
        }

        selected_addr
            = ipnet_ip4_get_local_addr_on_same_subnet((struct Ip_in_addr*) &dst_n,
                                                      cnetif, filter, filter_arg);

        if (selected_addr != IP_NULL
            && IPNET_IP4_IS_LINK_LOCAL(selected_addr) == IP_FALSE)
            return selected_addr;
    }

    /* Return any unicast address on the interface */
    if (cnetif != IP_NULL)
    {
#ifdef IPNET_USE_RFC5227
        /* Should not use a tentative address */
        for (addr = cnetif->inet4_addr_list; addr != IP_NULL; addr = addr->next)
        {
            if ((addr->type == IPNET_ADDR_TYPE_UNICAST)
                && (!IP_BIT_ISSET(addr->flags, IPNET_IP4_ADDR_FLAG_TENTATIVE)))
            {
                if (filter == IP_NULL ||
                    filter(&addr->ipaddr_n, IP_AF_INET, 0, filter_arg))
                    return (struct Ip_in_addr *) &addr->ipaddr_n;
            }
        }
#else
        addr = cnetif->inet4_addr_list;
        if (addr != IP_NULL && addr->type == IPNET_ADDR_TYPE_UNICAST)
        {
            if (filter == IP_NULL ||
                filter(&addr->ipaddr_n, IP_AF_INET, 0, filter_arg))
                return (struct Ip_in_addr *) &addr->ipaddr_n;
        }
#endif
    }

    return IP_NULL;
}

IP_GLOBAL IP_CONST struct Ip_in_addr *
ipnet_ip4_get_src_addr(Ip_u16                       vr,
                       IP_CONST struct Ip_in_addr   *dst_addr,
                       Ipnet_route_entry            *rt,
                       Ipnet_netif                  *netif)
{
    IP_CONST struct Ip_in_addr *src;

    ipnet_route_lock();
    src = ipnet_ip4_get_src_addr_rtl(vr, dst_addr, rt, netif, IP_NULL, IP_NULL);
    ipnet_route_unlock();
    return src;
}


IP_GLOBAL IP_CONST struct Ip_in_addr *
ipnet_ip4_get_src_addr_ext(Ip_u16                       vr,
                           IP_CONST struct Ip_in_addr   *dst_addr,
                           Ipnet_route_entry            *rt,
                           Ipnet_netif                  *netif,
                           Ip_src_addr_filter           filter,
                           void *                       filter_arg)
{
    IP_CONST struct Ip_in_addr *src;

    ipnet_route_lock();
    src = ipnet_ip4_get_src_addr_rtl(vr, dst_addr, rt, netif, filter, filter_arg);
    ipnet_route_unlock();
    return src;
}


/*
 *===========================================================================
 *                    ipnet_ip4_add_route_table
 *===========================================================================
 * Description: Adds a new route table.
 * Parameters:  vr - The virtual router the table should be added for.
 *              table - The ID of the table.
 * Returns:     0 = success, <0 = error code.
 *
 */
IP_GLOBAL int
ipnet_ip4_add_route_table(Ip_u16 vr, Ip_u32 table)
{
    int                          ret;
    Ipcom_route                 *rt_head;

    rt_head = ipcom_route_new_table(sizeof(struct Ip_in_addr) * 8,
                                    ipnet_route_notify_func_l);

    ip_assert(rt_head != IP_NULL);
    if (rt_head == IP_NULL)
        /* Can't initialize the stack */
        return IPNET_ERRNO(ENOMEM);

    ret = ipnet_route_set_rtab(IP_AF_INET, vr, table, rt_head);
    if (ret < 0)
        ipcom_route_free_table(rt_head);
    else
        IPCOM_LOG2(NOTICE, "Adding new IPv4 route table, virtual router %u, table ID %u",
                   vr, table);
    return ret;
}


/*
 *===========================================================================
 *                    ipnet_ip4_configure_route_table
 *===========================================================================
 * Description: Configures a new route table.
 * Parameters:  vr - The virtual router the table should be added for.
 *              table - The ID of the table.
 * Returns:     0 = success, <0 = error code.
 *
 */
IP_GLOBAL int
ipnet_ip4_configure_route_table(Ip_u16 vr, Ip_u32 table)
{
    struct Ipnet_route_add_param param;
    struct Ipnet_rt_metrics      metrics;
    struct Ip_in_addr            addr_n;
    struct Ip_in_addr            mask_n;
    int                          ret;

    (void) ipcom_inet_pton(IP_AF_INET, "255.255.255.255", &addr_n);
    ipcom_memset(&metrics, 0, sizeof(metrics));
    metrics.rmx_hopcount = IPNET_ROUTE_AUTOMATIC_ENTRY_HOPCOUNT;
    metrics.rmx_expire   = IPCOM_ADDR_INFINITE;
    ipcom_memset(&param, 0, sizeof(struct Ipnet_route_add_param));
    param.domain  = IP_AF_INET;
    param.vr      = vr;
    param.table   = table;
    param.key     = &addr_n;
    param.flags   = IPNET_RTF_X_BCAST_RO | IPNET_RTF_DONE | IPNET_RTF_REJECT | IPNET_RTF_HOST;
    param.metrics = &metrics;
    ret = ipnet_route_add(&param);
    if (ret < 0)
        return ret;

    (void) ipcom_inet_pton(IP_AF_INET, "224.0.0.0", &addr_n);
    (void) ipcom_inet_pton(IP_AF_INET, "240.0.0.0", &mask_n);
    param.netmask = &mask_n;
    param.flags   = IPNET_RTF_X_MCAST_RO | IPNET_RTF_REJECT | IPNET_RTF_DONE;
    ret = ipnet_route_add(&param);

    return ret;
}


/*
 *===========================================================================
 *                    ipnet_ip4_init_once
 *===========================================================================
 * Description: Initializes the IPv4 module.
 * Parameters:
 * Returns:     0 = success, 0< = error code.
 *
 */
IP_GLOBAL int
ipnet_ip4_init_once(void)
{
    int i;
    Ipnet_ip4_shared_data *shrd_ip4 = &ipnet_shared()->ip4;

#ifdef IPNET_DEBUG
#ifdef IPNET_USE_RFC1256
    ipnet_timeout_to_string((Ipnet_timeout_handler) ipnet_ip4_rfc1256_advertise,
                            (Ipnet_timeout_to_string_f) ipnet_ip4_rfc1256_advertise_tmo_to_string);
    ipnet_timeout_to_string((Ipnet_timeout_handler) ipnet_ip4_rfc1256_solicit,
                            (Ipnet_timeout_to_string_f) ipnet_ip4_rfc1256_solicit_tmo_to_string);
#endif
#endif /* IPNET_DEBUG */

    shrd_ip4->addr_slab
        = ipcom_slab_new("IPNET IPv4 address",
                         IPCOM_SLAB_F_NO_LOCKING | IPCOM_SLAB_F_ZERO | IPCOM_SLAB_F_FEW,
                         sizeof(Ipnet_ip4_addr_entry) + sizeof(Ipnet_mcast_addr),
                         0,
                         IP_NULL,
                         IP_NULL,
                         ipnet_shared()->memory_pool);

    shrd_ip4->addrs = ipcom_hash_new((Ipcom_hash_obj_func) ipnet_ip4_addr_obj_func,
                                     (Ipcom_hash_key_func) ipnet_ip4_addr_key_func,
                                     (Ipcom_hash_cmp_func) ipnet_ip4_addr_cmp_func);

    shrd_ip4->addrs_ignore_if = ipcom_hash_new((Ipcom_hash_obj_func) ipnet_ip4_addr_ignore_if_obj_func,
                                               (Ipcom_hash_key_func) ipnet_ip4_addr_ignore_if_key_func,
                                               (Ipcom_hash_cmp_func) ipnet_ip4_addr_ignore_if_cmp_func);

    if (shrd_ip4->addrs == IP_NULL || shrd_ip4->addrs_ignore_if == IP_NULL)
        return IPNET_ERRNO(ENOMEM);

    /*
     * Mapping from IP-protocol and IP-option to its corresponding
     * handler is read-only after initialization and shared by all
     * stack instances.
     */

    /*
     * A transport layer handler for a specific IP protcol can must be
     * registered with ipnet_ip4_reg_transport_layer().
     */
    for (i = 0; i < 256; i++)
    {
        ipnet_ip4_reg_transport_layer((Ip_u8) i,
                                      ipnet_ip4_unsupported_transport_layer_rx);
        ipnet_ip4_reg_opt_rx((Ip_u8) i,
                             ipnet_ip4_opt_unsupported_rx);
    }

    ipnet_ip4_reg_opt_rx(IP_IPOPT_RA, ipnet_ip4_opt_ra_rx);
    ipnet_ip4_reg_opt_rx(IP_IPOPT_TIMESTAMP, ipnet_ip4_opt_ts_rx);
    ipnet_ip4_reg_opt_rx(IP_IPOPT_LSRR, ipnet_ip4_opt_srr_rx);
    ipnet_ip4_reg_opt_rx(IP_IPOPT_SSRR, ipnet_ip4_opt_srr_rx);
    ipnet_ip4_reg_opt_rx(IP_IPOPT_RR, ipnet_ip4_opt_rr_rx);

#ifdef IPNET_USE_MCAST_ROUTING
    ipnet_ip4_reg_transport_layer(IP_IPPROTO_PIM,
                                  ipnet_pim_ip4_rx);
#endif
    /*
     * Only register handlers for ICMP and IGMP handlers when not
     * running in NAE mode. Those two protocols must be handled by the
     * master OS in NAE mode.
     */
#ifndef IPCOM_FORWARDER_NAE
    ipnet_ip4_reg_transport_layer(IP_IPPROTO_ICMP,
                                  ipnet_icmp4_input);
    ipnet_ip4_reg_transport_layer(IP_IPPROTO_IGMP,
                                  ipnet_igmp_input);
#endif

#ifdef IPNET_USE_NETLINK
    ipnet_rtnetlink_ip4_init();
#endif

    return 0;
}


/*
 *===========================================================================
 *                     ipnet_ip4_reg_transport_layer
 *===========================================================================
 * Description: Registers a handler for a specific IP protocol.
 * Parameters:  ip_proto - IP protocol to register handler for.
 *              trans_rx -
 * Returns:
 *
 */
IP_GLOBAL void
ipnet_ip4_reg_transport_layer(Ip_u8 ip_proto,
                              Ipnet_transport_layer_rx_func trans_rx)
{
    ipnet_ip4_transport_layer_rx[ip_proto] = trans_rx;
}



/*
 *===========================================================================
 *                         ipnet_ip4_get_addr_type
 *===========================================================================
 * Description: Returns type of the specified address.
 * Parameters:  ipaddr_n - The address for which the type will be returned.
 *              vr - The virtual router the address must be assiged to.
 *              netif - The network interface the address should be assigned
 *              to or IP_NULL if any interface might do.
 * Returns:     IPNET_ADDR_TYPE_xxx constant.
 */
IP_GLOBAL enum Ipnet_addr_type
ipnet_ip4_get_addr_type(Ip_u32 ipaddr_n, Ip_u16 vr, Ipnet_netif *netif)
{
    Ipnet_ip4_addr_entry *addr;

    addr = ipnet_ip4_get_addr_entry(ipaddr_n, vr, netif);
    while (addr != IP_NULL)
    {
        Ipnet_netif *this_netif = ipnet_ip4_addr_to_netif(addr);

        if ((netif == IP_NULL || netif == this_netif)
            && IP_BIT_ISSET(this_netif->ipcom.flags, IP_IFF_UP))
            return addr->type;

        addr = addr->next_dup_addr;
    }

    /* 255.255.255.255 broadcast. */
    if (ipaddr_n == IP_INADDR_BROADCAST)
        return IPNET_ADDR_TYPE_BROADCAST;

    /* any. */
    if (ipaddr_n == IP_INADDR_ANY)
        return IPNET_ADDR_TYPE_ANY;

    /* not to me. */
    return IPNET_ADDR_TYPE_NOT_LOCAL;
}



/*
 *===========================================================================
 *                         ipnet_ip4_get_addr_type2
 *===========================================================================
 * Description: Returns type of the specified address, interface must be specified.
 * Parameters:  ipaddr_n - The address for which the type will be returned.
 *              netif - The network interface the address must be assigned.
 * Returns:     IPNET_ADDR_TYPE_xxx constant.
 */
IP_GLOBAL enum Ipnet_addr_type
ipnet_ip4_get_addr_type2(Ip_u32 ipaddr_n, Ipnet_netif *netif)
{
    ip_assert(netif != IP_NULL);
    return ipnet_ip4_get_addr_type(ipaddr_n, netif->vr_index, netif);
}


/*
 *===========================================================================
 *                         ipnet_ip4_get_addr_entry
 *===========================================================================
 * Description: Returns the address entry for the specified address.
 * Parameters:  ipaddr_n - The address for which the type will be returned.
 *              vr - The virtual router the address must be assignd to.
 *              netif - The network interface the address should be assigned
 *              to or IP_NULL if any interface might do.
 * Returns:     The address entry or IP_NULL if no such address is assigned
 *              to the interface.
 */
IP_GLOBAL Ipnet_ip4_addr_entry *
ipnet_ip4_get_addr_entry(Ip_u32 ipaddr_n, Ip_u16 vr, Ipnet_netif *netif)
{
    Ipnet_ip4_addr_lookup  l;
    Ipnet_ip4_shared_data *shrd_ip4 = &ipnet_shared()->ip4;

    l.addr.s_addr = ipaddr_n;
    l.vr          = vr;

    if (netif == IP_NULL)
        return ipcom_hash_get(shrd_ip4->addrs_ignore_if, &l);

    l.ifindex     = netif->ipcom.ifindex;
    return ipcom_hash_get(shrd_ip4->addrs, &l);
}


/*
 *===========================================================================
 *                    ipnet_ip4_sendto
 *===========================================================================
 * Description: Finds out the source and destination address and dispatches
 *              the packet to ipnet_ip4_output(). The transport header
 *              checksum is also finished (if used).
 * Parameters:  sock - The socket to use when sending.
 *              to - The destination address address, ignored if the socket
 *              is in connected state.
 *              pkt - The packet data to send.
 * Returns:     >0 = application bytes sent, <0 = error code.
 *
 */
IP_GLOBAL int
ipnet_ip4_sendto(Ipnet_socket *sock, IP_CONST struct Ip_msghdr *msg, Ipcom_pkt *pkt)
{
    Ipnet_ip4_socket    *sock_ip4 = sock->ip4;
    int                  ret;
    Ipnet_dst_cache     *dst;
    Ipnet_flow_spec      flow_spec;
    Ipnet_ip4_layer_info ip4_info;
    Ipnet_data          *net = ipnet_pkt_get_stack_instance(pkt);

    /*
     * The stack instance owning this socket is the only instance that
     * may process packets in the context of the socket.
     */
    ip_assert(ipnet(ipnet_this()) == net);

#ifdef IPNET_USE_PER_SOCKET_VLAN_TAG
    if (sock->vlan_tag)
        ipnet_vlan_set_tag(pkt, sock->vlan_tag);
#endif

    pkt->fd           = sock->ipcom.fd;
    pkt->vr_index     = sock->vr_index;
    pkt->recurs_level = 0;

    /*
     * Add information needed to created the IP header
     */
    IPNET_IP4_SET_LAYER_INFO(pkt, &ip4_info);
    ip4_info.nexthop = IP_NULL;
    ip4_info.flags   = 0;
    ip4_info.id      = 0;
    ip4_info.proto   = (Ip_u8) sock->proto;
    ip4_info.opts    = sock_ip4->opts;
    if (sock_ip4->dont_frag)
        IP_BIT_SET(ip4_info.flags, IPNET_IP4_OPF_DONT_FRAG);
    if (sock_ip4->no_local_frag)
        IP_BIT_SET(ip4_info.flags, IPNET_IP4_OPF_NO_LOCAL_FRAG);

    /*
     * Find the destination cache entry
     */
    ret = ipnet_flow_spec_from_sock(&flow_spec,
                                    sock,
                                    msg,
                                    ipnet_ip4_flow_spec_from_sock);
    if (IP_UNLIKELY(ret < 0))
        goto errout;

    if (msg != IP_NULL && msg->msg_control != IP_NULL)
    {
        /*
         * This function might change part of the flow specification,
         * so it has to be located between ipnet_flow_spec_from_sock()
         * and ipnet_dst_cache_get()
         */
        ret = ipnet_ip4_apply_ancillary_data(sock,
                                             msg,
                                             &flow_spec,
                                             &ip4_info,
                                             pkt);
        if (ret < 0)
            goto errout;
 
        if (IP_BIT_ISSET(msg->msg_flags, IP_MSG_DONTROUTE))
            IP_BIT_SET(flow_spec.flags, IPNET_FSF_DONTROUTE);
    } 

    dst = ipnet_dst_cache_get(net, &flow_spec);
    if (IP_UNLIKELY(dst == IP_NULL))
    {
        /*
         * First time this flow is used, at least since the last flush
         * of the destination cache
         */
        ret = ipnet_dst_cache_new(net,
                                  &flow_spec,
                                  ipnet_ip4_dst_cache_local_tx_ctor,
                                  &dst);
        if (ret < 0)
            goto errout;
    }

    /*
     * Set time-to-live field and whether a copy of the packet should
     * be delivered to the loopback device.
     */
    switch (dst->to_type)
    {
    case IPNET_ADDR_TYPE_UNICAST:
    case IPNET_ADDR_TYPE_TENTATIVE:
    case IPNET_ADDR_TYPE_NOT_LOCAL:
        ip4_info.ttl = sock->uni_hop_limit;
        if (IP_LIKELY(ip4_info.ttl == 0))
            ip4_info.ttl = (Ip_u8)dst->neigh->netif->conf.inet.base_hop_limit;
        break;
    case IPNET_ADDR_TYPE_MULTICAST:
        ip4_info.ttl = sock->multi_hop_limit;
        if (IP_BIT_ISSET(sock->flags, IPNET_SOCKET_FLAG_LOOP_MULTICAST))
            IP_BIT_SET(pkt->flags, IPCOM_PKT_FLAG_LOOP_MCAST);
        break;
    default:
        /*
         * Broadcast
         */

        if ((dst->to_type == IPNET_ADDR_TYPE_BROADCAST || dst->to_type == IPNET_ADDR_TYPE_NETBROADCAST)
            && IP_BIT_ISFALSE(sock->ip4->flags, IPNET_SOCKET_FLAG_IP4_ALLOW_BROADCAST))
            /*
             * This socket does not allow sending packets to the
             * broadcast address
             */
        {
            IPCOM_LOG1(NOTICE, "IPv4: socket %d is not allowed to send broadcast packets",
                       sock->ipcom.fd);
            ret = IPNET_ERRNO(EACCES);
            goto errout;
        }
        ip4_info.ttl = 64;

        /*
         * Always loop broadcast packets.
         */
        IP_BIT_SET(pkt->flags, IPCOM_PKT_FLAG_LOOP_MCAST);
    }

    if (IP_LIKELY(IP_BIT_ISSET(sock->flags, IPNET_SOCKET_FLAG_ADDCHECKSUM)))
    /* ip4_info.chksum_ptr will be used in ipnet_dst_cache_tx */
    /* coverity[returned_pointer] */ 
        ip4_info.chksum_ptr = ipcom_pkt_get_data(pkt, sock->chk_offset);
    else
        ip4_info.chksum_ptr = IP_NULL;

    ret = ipnet_dst_cache_tx(dst, pkt);
    if (IP_UNLIKELY(ip4_info.nexthop))
        ipnet_neigh_release(ip4_info.nexthop);
    return ret;

 errout:
    ipcom_pkt_free(pkt);
    ipnet_neigh_release(ip4_info.nexthop);
    return ret;
}


/*
 *===========================================================================
 *                              ipnet_ip4_tx
 *===========================================================================
 * Description: Transmits a IPv4 packet. The packet must contain
 *              everything but the IPv4 header.
 * Parameters:  net - stack instance
 *              tos - Type of service
 *              ttl - Time to live
 *              ip_proto - IP-protocol
 *              src - IP source address, may be IP_NULL if the stack
 *                    should select a source address.
 *              dst - IP destination address
 *              ifindex - the egress interface to use or 0 to let the
 *                        stack select the interface
 *              pkt - packet to send.
 * Returns:     0 = success
 *              <0 = error code.
 *
 */
IP_GLOBAL int
ipnet_ip4_tx(Ipnet_data *net,
             Ip_u8 tos,
             Ip_u8 ttl,
             Ip_u8 ip_proto,
             IP_CONST Ip_u32 *src,
             IP_CONST Ip_u32 *dst,
             Ip_u32 ifindex,
             Ipcom_pkt *pkt)
{
    Ipnet_pkt_ip               *iphdr;
    IP_CONST struct Ip_in_addr *from;

    /*
     * Set egress interface.
     */
    pkt->ifindex = ifindex;

    /*
     * This is not a fragment.
     */
    pkt->offset  = 0;

    if (src)
        from = (struct Ip_in_addr *) src;
    else
    {
        /*
         * Must select a source address
         */
        from = ipnet_ip4_get_src_addr(pkt->vr_index,
                                      (struct Ip_in_addr *)dst,
                                      IP_NULL,
                                      IP_NULL);
        if (from == IP_NULL)
            /*
             * This would only happen during startup before any
             * addres has been assigned to this node.
             */
            return IPNET_ERRNO(EHOSTUNREACH);
    }

    /*
     * Create an IPv4 header, this is just so it is possible to call
     * ipnet_ip4_pkt_with_iphdr_tx().
     * No need to calculate the IP header checksum, the stack takes
     * care of that.
     */
    iphdr = ipcom_pkt_push_front(pkt, IPNET_IP_HDR_SIZE);
    iphdr->v_hl = 0x45;
    iphdr->tos  = tos;
    iphdr->off  = 0;
    iphdr->p    = ip_proto;
    iphdr->id   = (Ip_u16) (ipcom_random() & 0xffff);
    iphdr->ttl  = ttl;
    ipcom_memcpy(iphdr->dst, dst, sizeof(iphdr->dst));
    ipcom_memcpy(iphdr->src, &from->s_addr, sizeof(iphdr->src));

    pkt->ipstart = pkt->start;
    return ipnet_ip4_pkt_with_iphdr_tx(net, pkt, IP_NULL);
}


/*
 *===========================================================================
 *                      ipnet_ip4_pkt_with_iphdr_tx
 *===========================================================================
 * Description: Transmits a packet that already has an IPv4 header.
 * Parameters:  net - stack instance
 *              pkt - packet that includes an IP-header.
 *              rt_lookup_key - optional address to transmit the packet.
 * Returns:     0 = success
 *             <0 = error code
 *
 */
IP_GLOBAL int
ipnet_ip4_pkt_with_iphdr_tx(Ipnet_data *net,
                            Ipcom_pkt *pkt,
                            void *rt_lookup_key)
{
    Ipnet_flow_spec            flow_spec;
    Ipnet_dst_cache           *dst;
    Ipnet_ip4_layer_info       ip4_info;
    struct Ipnet_ip4_sock_opts opts;
    Ipnet_pkt_ip              *iphdr;
    void                     **ppchksum;

    /* */
    if (IP_UNLIKELY(pkt->recurs_level++ > IPCOM_PKT_MAX_RECURSE_LEVEL))
    {
        IPCOM_LOG0(WARNING, "Discarding IPv4 datagram, too deep recurs level.");
        ipcom_pkt_free(pkt);
        return IPNET_ERRNO(EHOSTUNREACH);
    }

    iphdr = ipcom_pkt_get_iphdr(pkt);

    /*
     * Add information needed to created the IP header
     */
    IPNET_IP4_SET_LAYER_INFO(pkt, &ip4_info);
    ip4_info.proto      = iphdr->p;
    ip4_info.ttl        = iphdr->ttl;
    ip4_info.nexthop    = IP_NULL;
    ip4_info.opts       = &opts;
    ip4_info.flags      = 0;
    IPNET_IP4_LAYER_SET_ID(&ip4_info, iphdr->id);

    if (IP_BIT_ISSET(iphdr->off, IPNET_OFF_DF))
        IP_BIT_SET(ip4_info.flags, IPNET_IP4_OPF_DONT_FRAG);

    ppchksum = ipcom_pkt_get_info(pkt, IPNET_PKT_INFO_L4_CHKSUM_PTR);
    if (ppchksum == IP_NULL)
        ip4_info.chksum_ptr = IP_NULL;
    else
    {
        ip4_info.chksum_ptr = *ppchksum;
        /*
         * Clear the checksum field; we may loop through a tunnel
         * device, and that could recalculate the checksum twice -
         * making it invalid
         */
        *ppchksum = IP_NULL;
    }

    /*
     * Store IP options, if any
     */
    opts.len = IPNET_IP4_GET_OPTS_OCTET_LEN(iphdr);
    if (opts.len < 0)
    {
        /* Invalid packet */
        ipcom_pkt_free(pkt);
        return -IP_ERRNO_EINVAL;
    }
    ipcom_memcpy(opts.opts, iphdr + 1, (Ip_size_t)opts.len);

    ipnet_ip4_flow_spec_from_pkt(&flow_spec, pkt, iphdr, IP_FALSE);

    /*
     * Use optional address in msg structure to get dst if specified
     */
    if (rt_lookup_key != IP_NULL)
        flow_spec.to.in = *(struct Ip_in_addr *)rt_lookup_key;

    dst = ipnet_dst_cache_get(net, &flow_spec);
    if (IP_UNLIKELY(dst == IP_NULL))
    {
        int ret;

        /*
         * This is a new flow. Lets create a destination cache entry
         * for it.
         */
        ret = ipnet_dst_cache_new(net,
                                  &flow_spec,
                                  ipnet_ip4_dst_cache_local_tx_ctor,
                                  &dst);
        if (ret < 0)
        {
            ipcom_pkt_free(pkt);
            return ret;
        }
    }

    /*
     * The IPv4 transmit handler will write a new header, remove the
     * current header since we copied all information from it
     * already.
     */
    pkt->start += opts.len + IPNET_IP_HDR_SIZE;

    if (rt_lookup_key == IP_NULL)
        IP_BIT_CLR(pkt->flags, IPCOM_PKT_FLAG_HAS_IP_HDR);

    /*
     * Deliver packet to the appropriate IPv4 transmit handler.
     */
    return ipnet_dst_cache_tx(dst, pkt);

}


#ifndef IPCOM_FORWARDER_NAE
/*
 *===========================================================================
 *                      ipnet_icmp_and_igmp_is_sane
 *===========================================================================
 * Description: Verifies the size and checksum of ICMP and IGMP packets.
 * Parameters:  pkt - ICMP or IGMP packet.
 * Returns:
 *
 */
IP_STATIC Ip_bool
ipnet_icmp_and_igmp_is_sane(Ipcom_pkt *pkt)
{
    Ip_u16 chksum;
    int    len = ipcom_pkt_get_length(pkt);
    Ipnet_data *net = ipnet_pkt_get_stack_instance(pkt);

    /*
     * Check that the message is big enough to hold the ICMP/IGMP header
     */
    if (len < IPNET_ICMP_HDR_SIZE)
    {
        IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_WARNING,
                          1, 1, IPCOM_WV_NETDEVENT_WARNING, IPCOM_WV_NETD_RECV,
                          ipnet_icmp_and_igmp_is_sane, IPCOM_WV_NETD_BADHLEN,
                          IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
        IPNET_STATS(net, icmp4_input_hdrsize++);
        IPCOM_MIB2(net, icmpInErrors++);
        IPCOM_MIB2_SYSWI_U32_ADD(net, v4, icmpStatsInErrors, 1);
        return IP_FALSE;
    }

    /*
     * Verify the ICMP checksum */
#ifdef IPCOM_USE_HW_CHECKSUM_RX
    if (IP_BIT_ISSET(pkt->flags, IPCOM_PKT_FLAG_HW_CHECKSUM))
        chksum = 0;
    else if (IP_BIT_ISSET(pkt->flags, IPCOM_PKT_FLAG_TL_CHECKSUM))
        chksum = ipcom_in_checksum_finish(pkt->chk);
    else
#endif /* IPCOM_USE_HW_CHECKSUM_RX */
        chksum = ipcom_in_checksum_pkt(pkt, 0);

    if (chksum != 0)
    {
        IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_WARNING,
                          1, 20, IPCOM_WV_NETDEVENT_WARNING, IPCOM_WV_NETD_RECV,
                          ipnet_icmp_and_igmp_is_sane, IPCOM_WV_NETD_BADSUM,
                          IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
        IPNET_STATS(net, icmp4_input_badchksum++);
        IP_PANIC2();
        IPCOM_MIB2(net, icmpInErrors++);
        IPCOM_MIB2_SYSWI_U32_ADD(net, v4, icmpStatsInErrors, 1);
        return IP_FALSE;
    }

    IPCOM_MIB2(net, ipInDelivers++);
    return IP_TRUE;
}



/*
 *===========================================================================
 *                       ipnet_icmp4_apply_redirect
 *===========================================================================
 * Description: Updates any destination cache that matches the redirect
 *              message with a new first hop.
 * Parameters:  dst - a destination cache entry
 *              user_data - pointer to information about the redirect
 * Returns:
 *
 */
IP_STATIC void
ipnet_icmp4_apply_redirect(Ipnet_dst_cache *dst,
                           void *user_data)
{
    struct Ipnet_icmp4_redirect_foreach *info = user_data;
    Ipnet_neigh                         *neigh = dst->neigh;

    /*
     * Read the domain directly, we do not want to affect
     * MSG_DONTROUTE entries.
     */
    if (IP_BIT_ISFALSE(dst->flow_spec.flags, IPNET_FSF_IPV6 | IPNET_FSF_DONTROUTE)
        && dst->flow_spec.to.in.s_addr == info->target.s_addr
        && neigh != IP_NULL
        && neigh->netif->ipcom.ifindex == info->ifindex
        && neigh->addr.in.s_addr == info->src.s_addr)
    {
        Ipnet_neigh *new_neigh;
        
        /* coverity[overrun-buffer-val] */
        new_neigh = ipnet_neigh_get(IP_AF_INET,
                                    &info->new_first_hop,
                                    neigh->netif,
                                    IPNET_NEIGH_CAN_CREATE);
        if (IP_LIKELY(new_neigh != IP_NULL))
        {
            dst->neigh = new_neigh;
            ipnet_neigh_release(neigh);
        }
    }
}

/*
 *===========================================================================
 *                       ipnet_icmp4_redirect_bcast_job
 *===========================================================================
 * Context:     Every network task; a broadcast job handler.
 * Description: In the stack instance specified by 'net', update any
 *              destination cache that matches the redirect message with a
 *              new first hop.
 * Parameters:  net - the running stack instance
 *              job - the broadcast job containing the packet.
 * Returns:
 *
 */
IP_STATIC void
ipnet_icmp4_redirect_bcast_job(Ipnet_data * net, Ipnet_broadcast_job *job)
{
    Ipcom_pkt                            *pkt = job->ptr;
    struct Ipnet_icmp4_redirect_foreach   data;
    Ipnet_pkt_ip                         *iphdr_red;
    Ipnet_pkt_ip                         *iphdr_orig;
    Ipnet_pkt_icmp                       *icmp;

    /* The IP header of the redirect message itself */
    iphdr_red = ipcom_pkt_get_iphdr(pkt);

    icmp = ipcom_pkt_get_data(pkt, 0);

    /* IP header of the original datagram that triggered the redirect */
    iphdr_orig = (Ipnet_pkt_ip *) icmp->data.redirect.ip;

    data.ifindex = pkt->ifindex;

    /* Sender IP address of the redirect message */
    ipcom_memcpy(&data.src, iphdr_red->src, sizeof(data.src));

    /* Destination IP address of the datagram that triggered the redirect */
    ipcom_memcpy(&data.target, iphdr_orig->dst, sizeof(data.target));

    /* IP address of the new first-hop node */
    ipcom_memcpy(&data.new_first_hop, icmp->data.redirect.gateway_addr, sizeof(data.new_first_hop));

    ipnet_dst_cache_foreach(net,
                            ipnet_icmp4_apply_redirect,
                            &data);
}


/*
 *===========================================================================
 *                       ipnet_icmp4_input_redirect
 *===========================================================================
 * Description: Handles ICMP redirect message.
 * Parameters:  ingress_netif - interface where the redirect was received
 *              dst - IP address of the receiver of the redirect
 *              pkt - the ICMP redirect packet
 * Returns:
 *
 */
IP_STATIC void
ipnet_icmp4_input_redirect(Ipnet_netif *ingress_netif,
                           IP_CONST struct Ip_in_addr *dst,
                           Ipcom_pkt *pkt)
{
    Ipnet_pkt_icmp                     *icmp = ipcom_pkt_get_data(pkt, 0);
    struct Ip_in_addr                   new_first_hop;
    Ipnet_ip4_addr_entry               *ae;
#ifdef IPCOM_USE_MIB2
    Ipnet_data                         *net = ipnet_ptr();
#endif

    /*
     * 3.2.2.2  Redirect: RFC-792
     *
     * A host SHOULD NOT send an ICMP Redirect message; Redirects are
     * to be sent only by gateways.
     *
     * A host receiving a Redirect message MUST update its routing
     * information accordingly.  Every host MUST be prepared to accept
     * both Host and Network Redirects and to process them as
     * described in Section 3.3.1.2 below.
     */

    IPCOM_MIB2(net, icmpInRedirects++);

    switch (icmp->code)
    {
    case IPNET_ICMP4_CODE_RED_NETWORK:
    case IPNET_ICMP4_CODE_RED_HOST:
        break;
    default:
        /* Invalid or unsupported code */
        goto freepkt;
    }

    if (!ingress_netif->conf.inet.icmp_redirect_receive)
        goto freepkt;
    
    /* IP-address of the new first-hop node */
    ipcom_memcpy(&new_first_hop,
                 icmp->data.redirect.gateway_addr,
                 sizeof(new_first_hop));

    /*
     * A Redirect message SHOULD be silently discarded if the new
     * gateway address it specifies is not on the same connected
     * (sub-) net through which the Redirect arrived [INTRO:2,
     * Appendix A], or if the source of the Redirect is not the
     * current first-hop gateway for the specified destination
     * (see Section 3.3.1).
     */
    ae = ipnet_ip4_get_addr_entry(dst->s_addr,
                                  ingress_netif->vr_index,
                                  ingress_netif);
    if (ae == IP_NULL ||
        (ae->ipaddr_n & ae->netmask_n) != (new_first_hop.s_addr & ae->netmask_n))
        /*
         * New gateway is on a different subnet than the
         * destination address this message was sent to.
         */
        goto freepkt;


    /*
     * The current next-hop for the destination is stored in its destination
     * cache entries (in each stack instance).  The broadcast job below updates
     * destination cache entries only if their current next-hop IP matches the 
     * sender of the redirect.
     *
     * Unlike for IPv6, there is no Target Link Level Address ICMP option,
     * we don't have to update any IsRouter flag, and the new next hop must
     * appear to be in the same subnet on which the redirect was received, i.e.
     * it must appear to be on-link.  So we don't need a special routine to
     * handle such things after all instances have updated any of their
     * matching destination cache entries (as we did for ICMPv6), and we
     * can use the default pkt/job free routine.
     */
    ipnet_pkt_broadcast_job(pkt,
                            ipnet_icmp4_redirect_bcast_job,
                            IP_NULL,
                            0);
    return; /* don't free the packet, ipnet_pkt_broadcast_job() takes ownership */

freepkt:
    ipcom_pkt_free(pkt);
}


/*
 *===========================================================================
 *                      ipnet_icmp4_update_dst_pmtu
 *===========================================================================
 * Description: Called for each destination cache entry. Entrues that matches
 *              the ICMP packet need-frag will get their path MTU lowered.
 * Parameters:  dst - a destination cache entry
 *              pkt_ptr - pointer to the ICMP destination unreachable,
 *                        need frag message.
 * Returns:
 *
 */
IP_STATIC void
ipnet_icmp4_update_dst_pmtu(Ipnet_dst_cache *dst, void *ctx)
{
    Ipnet_pmtu_cb_data *data = ctx;

    if (ipnet_flow_spec_domain(&dst->flow_spec) != IP_AF_INET)
        return;

    if (dst->flow_spec.vr == data->vr_index
        && IP_ADDR_UN_IP4(data->dst) == dst->flow_spec.to.in.s_addr
        && IP_ADDR_UN_IP4(data->src) == dst->laddr.in.s_addr)
    {
        ipnet_dst_cache_set_path_mtu(dst, data->new_path_mtu);
    }
}


/*
 *===========================================================================
 *                  ipnet_icmp4_input_addr_mask_request
 *===========================================================================
 * Description: Handles RFC 950 address mask request.
 * Parameters:  dst - destination cache entry for the request
 *              mask_n - pointer to where the mask should be stored.
 *              icmp_param - an ICMP param structure initialized from the request
 * Returns:     IP_TRUE a response was sent, IP_FALSE otherwise.
 *
 */
IP_STATIC Ip_bool
ipnet_icmp4_input_addr_mask_request(Ipnet_netif *netif,
                                    Ipnet_dst_cache *dst,
                                    Ip_u32 *mask_n,
                                    Ipnet_icmp_param *icmp_param)
{
    Ipnet_ip4_addr_entry *addr;

    icmp_param->type    = IPNET_ICMP4_TYPE_MASK_REPLY;
    icmp_param->code    = 0;
    icmp_param->ifindex = netif->ipcom.ifindex;

    if (dst->flow_spec.from.in.s_addr == ip_inaddr_any.s_addr)
    {
        /*
         * RFC 950
         *
         * If the requesting host does not know its own IP address, it
         * may leave the source field zero; the reply should then be
         * broadcast.
         */
        icmp_param->to.s_addr = IP_INADDR_BROADCAST;
        addr = netif->inet4_addr_list;
    }
    else
    {
        addr = ipnet_ip4_get_addr_entry(dst->flow_spec.to.in.s_addr,
                                        netif->vr_index,
                                        netif);

        if (addr == IP_NULL || addr->type != IPNET_ADDR_TYPE_UNICAST)
            return IP_FALSE;
    }
    IP_SET_32ON16(mask_n, addr->netmask_n);

    return (ipnet_icmp4_send(icmp_param, IP_FALSE) >= 0
            || icmp_param->recv_pkt == IP_NULL);
}


/*
 *===========================================================================
 *                    ipnet_icmp4_switch_to_socket_stack
 *===========================================================================
 * Description: Switch to the stack instance owning the socket that sent
 *              the packet that elicited a redirect, or destination 
 *              unreachable, or time exceeded message.
 * Parameters:  dst - Destination cache entry matching the packet
 *              pkt - The received ICMP4 message, pkt->start is the offset to
 *                    the ICMP4 header.
 *              sock - The affected socket.
 *              proto - The transport protocol type.
 *              transport_hdr - The transport header in 'pkt'
 * Returns:     IP_FALSE - The packet has been handled (freed or sent to another
 *                         stack instance).
 *              IP_TRUE - Processing should continue in this stack instance.
 */
IP_STATIC Ip_bool
ipnet_icmp4_switch_to_socket_stack(Ipnet_dst_cache *dst,
                                   Ipcom_pkt *pkt,
                                   Ipnet_socket **sock,
                                   Ip_u16 *proto,
                                   void  **transport_hdr)
{
    Ipnet_pkt_icmp  *icmp_hdr;
    Ipnet_pkt_ip    *failing_ip_pkt;
    Ip_u32           fsrc_addr_n;
    Ip_u32           fdst_addr_n;
    Ip_u16           fsport = 0;
    Ip_u16           fdport = 0;
    int              sock_stack_idx;

    icmp_hdr = ipcom_pkt_get_data(pkt, 0);
    failing_ip_pkt = (Ipnet_pkt_ip *) icmp_hdr->data.failing_pkt.ip;

    fdst_addr_n = IPNET_IP4_GET_IPADDR(failing_ip_pkt->dst);
    fsrc_addr_n = IPNET_IP4_GET_IPADDR(failing_ip_pkt->src);
    *proto = failing_ip_pkt->p;
    *transport_hdr = (Ip_u8 *)failing_ip_pkt + IPNET_IP4_GET_HDR_OCTET_LEN(failing_ip_pkt);

    if (*proto == IP_IPPROTO_UDP || *proto == IP_IPPROTO_TCP)
    {
        Ipnet_pkt_udp  *udp_pkt = *transport_hdr;
        fsport = ip_ntohs(udp_pkt->sport);
        fdport = ip_ntohs(udp_pkt->dport);
    }

    ipnet_reachable_sockets_rdlock();

    /* Find the affected socket */
    *sock = ipnet_sock_ip4_lookup(pkt->vr_index, *proto,
                                  &fsrc_addr_n, fsport,
                                  &fdst_addr_n, fdport);

    sock_stack_idx = *sock ? (*sock)->stack_instance_idx : -1;

    ipnet_reachable_sockets_rdunlock();

    if (sock_stack_idx >= 0 &&
        !ipnet_dst_do_on_stack_idx(sock_stack_idx,
                                   &dst->flow_spec,
                                   pkt,
                                   (Ipnet_dst_cache_rx_func)ipnet_icmp4_input,
                                   ipnet_ip4_dst_cache_rx_ctor))
    {
        /* Packet was relayed to the stack instance managing sock. */
        return IP_FALSE;
    }

    return IP_TRUE;
}


/*
 *===========================================================================
 *                    ipnet_icmp4_pmtu_cb_data_init
 *===========================================================================
 * Description: Initialize Icmp_pmtu_cb_data from packet
 * Parameters:  data - the Ipnet_pmtu_cb_data to initialize
 *              pkt - The received ICMPv4 message, pkt->start is the offset
 *                    of the ICMPv4 header.
 *              flags - encodes the failing IP header length and the 
 *                      transport protocol
 * Returns:
 *
 */
IP_STATIC void
ipnet_icmp4_pmtu_cb_data_init(Ipnet_pmtu_cb_data *data,
                              const Ipcom_pkt *pkt,
                              int flags)
{
    Ipnet_pkt_icmp  *icmp_hdr;
    Ipnet_pkt_ip    *failing_ip_pkt;
    Ip_u16           failing_ip_hdr_len = (Ip_u16)(flags & 0xffff);
    Ip_u16          *trans_ports;
    int              proto;

    data->domain = IP_AF_INET;
    data->vr_index = pkt->vr_index;
    
    icmp_hdr = ipcom_pkt_get_data(pkt, 0);

    data->new_path_mtu = IP_GET_NTOHL(icmp_hdr->data.failing_pkt.next_hop_mtu);

    failing_ip_pkt = (Ipnet_pkt_ip *) icmp_hdr->data.failing_pkt.ip;

    IP_ADDR_UN_IP4(data->dst) = IPNET_IP4_GET_IPADDR(failing_ip_pkt->dst);
    IP_ADDR_UN_IP4(data->src) = IPNET_IP4_GET_IPADDR(failing_ip_pkt->src);

#ifdef IPCOM_USE_INET6
    /* Make IPv4-mapped IPv6 addresses */
    data->dst.in6.in6.addr32[0] = 0; data->dst.in6.in6.addr32[1] = 0;
    data->dst.in6.in6.addr16[4] = 0; data->dst.in6.in6.addr16[5] = 0xffff;

    data->src.in6.in6.addr32[0] = 0; data->src.in6.in6.addr32[1] = 0;
    data->src.in6.in6.addr16[4] = 0; data->src.in6.in6.addr16[5] = 0xffff;

    data->dst_zone_id = 0;
    data->src_zone_id = 0;
#endif

    data->dst_port = data->src_port = 0;

    proto = flags >> 16;
    data->proto = (Ip_u16)proto;

    trans_ports = (Ip_u16 *)((Ip_u8 *)failing_ip_pkt + failing_ip_hdr_len);

    if (proto == IP_IPPROTO_UDP || proto == IP_IPPROTO_TCP || proto == IP_IPPROTO_SCTP)
    {
        data->src_port = ip_ntohs(trans_ports[0]);
        data->dst_port = ip_ntohs(trans_ports[1]);
    }
}


/*
 *===========================================================================
 *                    ipnet_icmp4_packet_too_big_bcast_job
 *===========================================================================
 * Context:     Called in each network task as a broadcast job.
 * Description: Processes a Destination Unreachable / Needs Fragmentation
 *              ICMP error message (used by path MTU discovery)
 *              for a particular stack instance.
 * Parameters:  net - the stack instance
 *              job - job->ptr contains the received ICMP message, and
 *                    job->flags encodes both the failing IP header length
 *                    and the transport protocol.
 *              pkt->start is the offset of the ICMP header.
 * Returns:
 *
 */
IP_STATIC void
ipnet_icmp4_packet_too_big_bcast_job(Ipnet_data * net, Ipnet_broadcast_job *job)
{
    Ipcom_pkt               *pkt = job->ptr;
    Ipnet_pmtu_cb_data       data;

    /* first fill out PMTU callback structure */

    ipnet_icmp4_pmtu_cb_data_init(&data, pkt, job->flags);
        
    /* Now adjust any matching destination cache entries on this stack instance */

    ipnet_dst_cache_foreach(net,
                            ipnet_icmp4_update_dst_pmtu,
                            &data);

    /* Now notify TCP of the PMTU change (for this stack instance) */

#ifdef IPTCP
    iptcp_net_pmtu_update(net, &data);
#endif

    /*
     * Note, SCTP is notified in ipnet_icmp6_packet_too_big_bcast_job_finish()
     * if necessary.
     */

}

#ifdef IPSCTP
/*
 *===========================================================================
 *                    ipnet_icmp4_packet_too_big_bcast_job_finish
 *===========================================================================
 * Context:     Some arbitrary network daemon task.
 * Description: Notify SCTP of a path MTU change after destination cache
 *              entries are updated on all stack instances; and free packet.
 * Parameters:  net - the stack instance of caller or IP_NULL
 *              job - job->ptr contains the received ICMP message, and
 *                    job->flags contains the transport protocol.
 * Returns:
 *
 */
IP_STATIC void
ipnet_icmp4_packet_too_big_bcast_job_finish(Ipnet_data * net, Ipnet_broadcast_job *job)
{
    Ipcom_pkt               *pkt = job->ptr; /* pkt->start locates the ICMP header */
    Ipnet_pmtu_cb_data       data;

    if (net != IP_NULL)
    {
        /* 
         * When net == IP_NULL, the broadcast job could not be scheduled
         * and we just free the packet.
         */

        /* First fill out PMTU callback structure. A bit ugly to have to repeat this. */
    
        ipnet_icmp4_pmtu_cb_data_init(&data, pkt, job->flags);

        ipsctp_pmtu_update(&data);
    }

    ipcom_pkt_free(pkt);
}
#endif /* IPSCTP */


/*
 *===========================================================================
 *                    ipnet_icmp4_input_packet_too_big
 *===========================================================================
 * Description: Processes ICMPv4 Destination Unreachable / Needs Fragmentation
 * Parameters:  dst - destination cache entry the ICMP packet matches.
 *              pkt - The received data, pkt->start is the offset to the ICMP
 *              header.
 * Returns:
 *
 */
IP_STATIC void
ipnet_icmp4_input_packet_too_big(Ipcom_pkt *pkt)
{
    Ipnet_pkt_icmp  *icmp_hdr;
    Ipnet_pkt_ip    *failing_ip_pkt;
    Ip_u8            proto;
    Ip_u16           failing_ip_hdr_len;
#ifdef IPSCTP
    int              transport_len;
#endif

    icmp_hdr = ipcom_pkt_get_data(pkt, 0);

    failing_ip_pkt = (Ipnet_pkt_ip *) icmp_hdr->data.failing_pkt.ip;

    proto = failing_ip_pkt->p;

    failing_ip_hdr_len = (Ip_u16)IPNET_IP4_GET_HDR_OCTET_LEN(failing_ip_pkt);

    /*
     * We could conceivably do some sort of validation for TCP against
     * the ports and TCP sequence number...
     */

#ifdef IPSCTP

    /*
     * Note, by checks done in ipnet_icmp4_input(), at this point
     * we know that the packet length (len) is at least
     * IPNET_ICMP_HDR_SIZE + failing_ip_pkt_len + 8.
     */

    transport_len = ipcom_pkt_get_part_length(pkt)
        - IPNET_ICMP_HDR_SIZE - failing_ip_hdr_len;

    if (proto == IP_IPPROTO_SCTP)
    {
        /*
         * Hmm, verification may actually require only the first 8
         * bytes of the SCTP header (i.e. ports and vtag), if the
         * vtag is nonzero.
         */
        if (transport_len < IPSCTP_SIZE_SCTP_HDR ||
            !ipsctp_icmp4_validate(pkt))
        {
            goto free_pkt;
        }
    }
#endif

    ipnet_pkt_broadcast_job(pkt,
                            ipnet_icmp4_packet_too_big_bcast_job,
#ifdef IPSCTP
                            ipnet_icmp4_packet_too_big_bcast_job_finish,
#else
                            IP_NULL,  /* default free routine */
#endif
                            (proto << 16) | failing_ip_hdr_len);

    /* ipnet_pkt_broadcast_job() always takes ownership of the packet */
    return;
    
#ifdef IPSCTP
free_pkt:

    ipcom_pkt_free(pkt);
#endif
}


/*
 *===========================================================================
 *                    ipnet_icmp4_input
 *===========================================================================
 * Description: Processes incoming ICMPv4 packets.
 * Parameters:  dst - destination cache entry the ICMP packet matches.
 *              pkt - The received data, pkt->start is the offset to the ICMP
 *              header.
 * Returns:
 *
 */
IP_STATIC void
ipnet_icmp4_input(Ipnet_dst_cache *dst,
                  Ipcom_pkt *pkt)
{
    Ipnet_icmp_param     icmp_param;
    Ipnet_pkt_icmp      *icmp_hdr;
    int                  icmp_len;
    int                  ret;
    enum Ipnet_addr_type addr_type;
    Ipnet_netif         *netif;
    Ipnet_data          *net = dst->net;
    Ipnet_sig           *sig;

    /*
     * Have we been here before? Set sig non-null if the packet has been relayed
     * to this stack instance from another instance; otherwise, sig is IP_NULL.
     */
    sig = ipcom_pkt_get_info(pkt, IPNET_PKT_INFO_SIG);
    if (sig != IP_NULL 
        && (sig->sig_type != IPNET_SIG_DST_RX ||
            sig->d.dst_rx.fun != (Ipnet_dst_cache_rx_func)ipnet_icmp4_input))
        sig = IP_NULL;

    if (!sig)
    {
        if (!ipnet_icmp_and_igmp_is_sane(pkt))
        {
            ipcom_pkt_free(pkt);
            return;
        }
        IPCOM_WV_MARKER_1 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_VERBOSE,
                           1, 18, IPCOM_WV_NETDEVENT_START, ipnet_icmp4_input,
                           IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
        IPNET_STATS(net, icmp4_input++);
        IPCOM_MIB2(net, icmpInMsgs++);
        IPCOM_MIB2_SYSWI_U32_ADD(net, v4, icmpStatsInMsgs, 1);
    }

    /* we don't presently handle segmented ICMP packets */
    icmp_len = ipcom_pkt_get_part_length(pkt);
    icmp_hdr = ipcom_pkt_get_data(pkt, 0);

    if (!sig)
    {
        IPCOM_MIB2_SYSWI_U32_ADD(net, v4, icmpMsgStatsInPkts[icmp_hdr->type], 1);

        if (icmp_hdr->type == IPNET_ICMP4_TYPE_ECHO_REPLY)
        {
            IPCOM_MIB2(net, icmpInEchoReps++);
            (void)ipnet_ip4_deliver_to_raw_sock(dst, pkt, IP_TRUE);
            return;
        }

        /*
         * UNIX Network Programming - The Sockets API - 3:rd ed, chapter
         * 28.4
         *
         * Most ICMP packets are passed to a raw socket after kernel has
         * finished processing the ICMP message. Berkley-derived
         * implementations pass all received ICMP packets to a raw socket
         * other than echo request, timestamp request and address mask
         * request. These three ICMP messages are processed entirely by
         * the kernel
         */
        if (icmp_hdr->type != IPNET_ICMP4_TYPE_ECHO_REQUEST)
            /*
             * Give a copy of the packet to all raw sockets. Timestamp
             * request and address mask request IS passed to raw sockets
             * since those are currently not handled by IPNET.
             */
            (void)ipnet_ip4_deliver_to_raw_sock(dst, pkt, IP_FALSE);
    }

    netif = ipnet_if_indextonetif(dst->flow_spec.vr,
                                  dst->flow_spec.ingress_ifindex);
    if (netif==IP_NULL)
    {
        IPCOM_LOG0(DEBUG,"Finding netif fail. ");
        goto cleanup;
    }
    if (!sig)
    {
        if (netif->conf.inet.icmp_ignore_broadcast)
        {
            addr_type = ipnet_ip4_get_addr_type2(dst->flow_spec.to.in.s_addr,
                                                 (IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_LOOPBACK)
                                                  ? ipnet_if_indextonetif(pkt->vr_index, pkt->ifindex)
                                                  : netif));

            if (addr_type == IPNET_ADDR_TYPE_NETBROADCAST
                || addr_type == IPNET_ADDR_TYPE_BROADCAST)
            {
                IPCOM_LOG2(DEBUG,"SMURF attack detected! ignoring icmp from %s on %s.. ",
                           ipcom_inet_ntop(IP_AF_INET,
                                           &dst->flow_spec.from,
                                           net->log_buf,
                                           sizeof(net->log_buf)),
                           netif->ipcom.name);
                goto cleanup;

            }
        }
    }

    ipnet_icmp4_param_init(&icmp_param, pkt);

    switch (icmp_hdr->type)
    {
    case IPNET_ICMP4_TYPE_ECHO_REQUEST:

        if (netif->conf.inet.icmp_ignore_echo_req)
        {
            IPCOM_LOG2(DEBUG, "ignore echo request from %s on %s",
                       ipcom_inet_ntop(IP_AF_INET,
                                       &dst->flow_spec.from,
                                       net->log_buf,
                                       sizeof(net->log_buf)),
                       netif->ipcom.name);
            goto cleanup;
        }

        /* Send a echo reply message */
        IPCOM_LOG3(DEBUG, "echo request from %s to %s on %s",
                   ipcom_inet_ntop(IP_AF_INET,
                                   &dst->flow_spec.from,
                                   net->log_buf,
                                   sizeof(net->log_buf)),
                   ipcom_inet_ntop(IP_AF_INET,
                                   &dst->flow_spec.to,
                                   net->log_buf + IP_INET_ADDRSTRLEN,
                                   sizeof(net->log_buf)- IP_INET_ADDRSTRLEN),
                   netif->ipcom.name);
        IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_INFO,
                          1, 21, IPCOM_WV_NETDEVENT_INFO, IPCOM_WV_NETD_RECV,
                          ipnet_icmp4_input, IPCOM_WV_NETD_INFO_RECEIVE,
                          IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
        IPNET_STATS(net, icmp4_input_echo_request++);
        IPCOM_MIB2(net, icmpInEchos++);
        icmp_param.type = IPNET_ICMP4_TYPE_ECHO_REPLY;
        icmp_param.code = 0;
        ret = ipnet_icmp4_send(&icmp_param, IP_FALSE);
        if (ret < 0 && icmp_param.recv_pkt != IP_NULL)
            /* ipnet_icmp4_send() did not free the orginal packet */
            goto cleanup;
        return;

    case IPNET_ICMP4_TYPE_DST_UNREACHABLE:
    case IPNET_ICMP4_TYPE_TIME_EXCEEDED:
        {
            Ipnet_socket *sock = IP_NULL;
            Ip_u16        proto;
            void         *transport_hdr;
            Ipnet_pkt_ip    *failing_ip_pkt;
            unsigned  failing_ip_hdr_len;

            failing_ip_pkt = (Ipnet_pkt_ip *) icmp_hdr->data.failing_pkt.ip;
            failing_ip_hdr_len = IPNET_IP4_GET_HDR_OCTET_LEN(failing_ip_pkt);


            if (!sig)
            {
                IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_INFO,
                                  1, 22, IPCOM_WV_NETDEVENT_INFO, IPCOM_WV_NETD_RECV,
                                  ipnet_icmp4_input, IPCOM_WV_NETD_INFO_RECEIVE,
                                  IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
                IPNET_STATS(net, icmp4_input_dst_unreach++);
                if(icmp_hdr->type == IPNET_ICMP4_TYPE_DST_UNREACHABLE)
                    IPCOM_MIB2(net, icmpInDestUnreachs++);
                else if(icmp_hdr->type == IPNET_ICMP4_TYPE_TIME_EXCEEDED)
                    IPCOM_MIB2(net, icmpInTimeExcds++);

                if (failing_ip_hdr_len < IPNET_IP_HDR_SIZE ||
                    icmp_len < IPNET_ICMP_HDR_SIZE + failing_ip_hdr_len + 8)
                {
                    IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_WARNING,
                                      1, 23, IPCOM_WV_NETDEVENT_WARNING, IPCOM_WV_NETD_RECV,
                                      ipnet_icmp4_input, IPCOM_WV_NETD_BADHLEN,
                                      IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
                    IPNET_STATS(net, icmp4_input_hdrsize2++);
                    IPCOM_MIB2(net, icmpInErrors++);
                    IPCOM_MIB2_SYSWI_U32_ADD(net, v4, icmpStatsInErrors, 1);
                    goto cleanup;
                }
            }

            if (icmp_hdr->type == IPNET_ICMP4_TYPE_DST_UNREACHABLE
                && icmp_hdr->code == IPNET_ICMP4_CODE_DST_NEEDFRAG)
            {
                if (netif->conf.inet.enable_path_mtu_discovery)
                {
                    ipnet_icmp4_input_packet_too_big(pkt);
                    return;
                }
                else goto cleanup;
            }


            /* Relay the meesage to stack instance owning affected socket */ 
            if (!ipnet_icmp4_switch_to_socket_stack(dst, pkt, &sock, 
                                                    &proto, &transport_hdr))
                /* The packet has been relayed to the socket stack instance */
                return;

            if (sock != IP_NULL
                && IP_BIT_ISFALSE(sock->flags, IPNET_SOCKET_FLAG_CONNECTED | IPNET_SOCKET_FLAG_CONNECTING))
                /* Notify only connected sockets */
                sock = IP_NULL;

            /* This stack instance "owns" the socket, which is therefore stable. */

#ifdef IPSCTP
            if (proto == IP_IPPROTO_SCTP)
                /*
                 * SCTP need to be called AFTER the path MTU has been
                 * changed. Unlike TCP, SCTP need to be called for
                 * other types of unreachable errors
                 */
                ipsctp_icmp4_cb(pkt);
#endif

            if (sock != IP_NULL)
            {
                IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_INFO,
                                  1, 24, IPCOM_WV_NETDEVENT_INFO, IPCOM_WV_NETD_RECV,
                                  ipnet_icmp4_input, IPCOM_WV_NETD_INFO_RECEIVE,
                                  IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
                IPNET_STATS(net, icmp4_input_dst_unreach_match++);

#ifdef IPTCP
                if (sock->tcb != IP_NULL)
                {
                    /* 
                     * If a whole TCP header is present, inform 
                     * TCP about the error on this socket.
                     */
                    if (icmp_len >= IPNET_ICMP_HDR_SIZE + failing_ip_hdr_len + IPTCP_TCP_HDR_SIZE)
                        iptcp_icmp4_report(sock, icmp_hdr->type, icmp_hdr->code, transport_hdr);
                    break;
                }
#endif

                if (icmp_hdr->type == IPNET_ICMP4_TYPE_TIME_EXCEEDED)
                {
                    switch (icmp_hdr->code)
                    {
                    case IPNET_ICMP4_CODE_TIM_TTL:
                    case IPNET_ICMP4_CODE_TIM_REASSEMBLY:
                        sock->ipcom.so_errno = IP_ERRNO_EHOSTUNREACH;
                        break;
                    default:
                        IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_WARNING,
                                          1, 25, IPCOM_WV_NETDEVENT_WARNING, IPCOM_WV_NETD_RECV,
                                          ipnet_icmp4_input, IPCOM_WV_NETD_BADTYPE,
                                          IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
                        IPNET_STATS(net, icmp4_input_dst_unreach_badcode++);
                        goto cleanup;
                    }
                }
                else
                {
                    switch (icmp_hdr->code)
                    {
                    case IPNET_ICMP4_CODE_DST_UNREACH_NET:
                        sock->ipcom.so_errno = IP_ERRNO_ENETUNREACH;
                        break;
                    case IPNET_ICMP4_CODE_DST_UNREACH_HOST:
                        sock->ipcom.so_errno = IP_ERRNO_EHOSTUNREACH;
                        break;
                    case IPNET_ICMP4_CODE_DST_UNREACH_PROTO:
                        sock->ipcom.so_errno = IP_ERRNO_EPROTONOSUPPORT;
                        break;
                    case IPNET_ICMP4_CODE_DST_UNREACH_PORT:
                        sock->ipcom.so_errno = IP_ERRNO_ECONNREFUSED;
                        break;
                    default:
                        IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_WARNING,
                                          1, 26, IPCOM_WV_NETDEVENT_WARNING, IPCOM_WV_NETD_RECV,
                                          ipnet_icmp4_input, IPCOM_WV_NETD_BADTYPE,
                                          IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
                        IPNET_STATS(net, icmp4_input_dst_unreach_badcode++);
                        goto cleanup;
                    }
                }

                /* Wake up processes sleeping on the socket. */
                ipnet_sock_data_avail(sock, sock->ipcom.so_errno, IP_SHUT_RDWR);
            }
            else
            {
                IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_INFO,
                                  1, 27, IPCOM_WV_NETDEVENT_INFO, IPCOM_WV_NETD_RECV,
                                  ipnet_icmp4_input, IPCOM_WV_NETD_INFO_RECEIVE,
                                  IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
                IPNET_STATS(net, icmp4_input_dst_unreach_nomatch++);
            }
        }
        break;

    case IPNET_ICMP4_TYPE_REDIRECT:
        ipnet_icmp4_input_redirect(netif,
                                   &dst->flow_spec.to.in,
                                   pkt);
        return; /* pkt consumed */

    case IPNET_ICMP4_TYPE_TSTAMP_REQUEST:
        if (netif->conf.inet.icmp_ignore_timestamp_req)
        {
            IPCOM_LOG2(DEBUG, "ignore timestamp request from %s on %s",
                       ipcom_inet_ntop(IP_AF_INET,
                                       &dst->flow_spec.from,
                                       net->log_buf,
                                       sizeof(net->log_buf)),
                       netif->ipcom.name);
            goto cleanup;
        }
        IPCOM_MIB2(net, icmpInTimestamps++);
        icmp_param.type = IPNET_ICMP4_TYPE_TSTAMP_REPLY;
        icmp_param.code = 0;
        ret = ipnet_icmp4_send(&icmp_param, IP_FALSE);
        if (ret < 0 && icmp_param.recv_pkt != IP_NULL)
            /* ipnet_icmp4_send() did not free the orginal packet */
            goto cleanup;
        return;

#ifdef IPNET_USE_RFC1256
    case IPNET_ICMP4_TYPE_ROUTER_ADVERT:
    case IPNET_ICMP4_TYPE_ROUTER_SOLICIT:

        /* 
         * Handle router advertisements and router solicitations on the
         * primary  stack instance.
         */
        if (!ipnet_dst_do_on_stack_idx(ipnet_primary_instance_idx(),
                                       &dst->flow_spec,
                                       pkt,
                                       (Ipnet_dst_cache_rx_func)ipnet_icmp4_input,
                                       ipnet_ip4_dst_cache_rx_ctor))
        {
            /*
             * The packet has been relayed to the primary stack instance
             * for processing.
             */
            return;
        }
        if (icmp_hdr->type == IPNET_ICMP4_TYPE_ROUTER_ADVERT)
        {
            ipnet_ip4_rfc1256_advertise_input(netif, icmp_hdr, icmp_len);
        }
        else
        {
            ipnet_ip4_rfc1256_solicit_input(dst, netif, icmp_hdr, icmp_len);
        }
        break;
#endif

    case IPNET_ICMP4_TYPE_MASK_REQUEST:
        IPCOM_MIB2(net, icmpInAddrMasks++);
        if (netif->inet4_addr_list != IP_NULL
            && netif->inet4_addr_list->type == IPNET_ADDR_TYPE_UNICAST
            && netif->conf.inet.icmp_send_addr_mask
            && ipcom_pkt_get_length(pkt) == 12 /* Length of ICMP address mask request */)
        {
            if (ipnet_icmp4_input_addr_mask_request(netif,
                                                    dst,
                                                    &icmp_hdr->data.addrmask.mask,
                                                    &icmp_param))
                return;
        }
        break;

    case IPNET_ICMP4_TYPE_MASK_REPLY:
        IPCOM_MIB2(net, icmpInAddrMaskReps++);
        break;

    case IPNET_ICMP4_TYPE_SOURCEQUENCH:
        IPCOM_MIB2(net, icmpInSrcQuenchs++);
        break;

    case IPNET_ICMP4_TYPE_TSTAMP_REPLY:
        IPCOM_MIB2(net, icmpInTimestampReps++);
        break;

    case IPNET_ICMP4_TYPE_PARAMPROB:
        IPCOM_MIB2(net, icmpInParmProbs++);
        break;

    default:
        break;
    }

 cleanup:
    ipcom_pkt_free(pkt);
}
#endif /* !IPCOM_FORWARDER_NAE */

IP_STATIC int
ipnet_ip4_opt_icmp(Ipnet_icmp_param *icmp_param, Ipnet_ip4_opt_param_t *params)
{
#ifdef IPCOM_USE_MIB2
    Ipnet_data  *net = ipnet_ptr();
    Ipnet_netif *netif = ipnet_if_indextonetif(params->pkt->vr_index, params->pkt->ifindex);

    IPCOM_MIB2(net, ipInHdrErrors++);
    IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsInHdrErrors, 1);
    IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsInHdrErrors, 1, netif, ipnet_instance_idx(net));
#endif


    /*
    * Copy all options so they can be restored to their original
    * value in case of error.
    */
    ipcom_memcpy((Ip_u8 *) params->ip_hdr + IPNET_IP_HDR_SIZE,
                 params->options,
                 params->optsize);

    (void) ipnet_icmp4_send(icmp_param, IP_FALSE);
    ipcom_pkt_free(params->pkt);

    return IPNET_ERRNO(EINVAL);
}

IP_STATIC int
ipnet_ip4_opt_icmp_error(Ip_u8 type, Ip_u8 code, Ipnet_ip4_opt_param_t *params)
{
    Ipnet_icmp_param  icmp_param;

    ipnet_icmp4_param_init(&icmp_param, params->pkt);

    icmp_param.type                 = type;
    icmp_param.code                 = code;

    return ipnet_ip4_opt_icmp(&icmp_param, params);
}

IP_STATIC int
ipnet_ip4_opt_icmp_param_prob(Ipnet_pkt_ip_opt *opt, Ip_u8 param_prob, Ipnet_ip4_opt_param_t *params)
{
    Ipnet_icmp_param  icmp_param;

    ipnet_icmp4_param_init(&icmp_param, params->pkt);

    icmp_param.type                 = IPNET_ICMP4_TYPE_PARAMPROB;
    icmp_param.code                 = 0; /* IP Header is invalid, offset used. */
    icmp_param.data.param_pointer   = (Ip_u8) ((Ip_u8) ((char *)opt - (char *)params->ip_hdr) + param_prob);

    return ipnet_ip4_opt_icmp(&icmp_param, params);
}

IP_INLINE int
ipnet_ip4_opt_done(Ipnet_ip4_opt_param_t *params)
{
    if (params->need_cksum)
    {
        params->ip_hdr->sum = 0;
        params->ip_hdr->sum = ipcom_in_checksum(params->ip_hdr, ipnet_ip4_get_hdr_octet_len(params->ip_hdr));
    }

    return ipnet_dst_cache_rx(params->dst, params->pkt);
}

IP_STATIC int
ipnet_ip4_opt_input(Ipnet_pkt_ip_opt *opt, Ipnet_ip4_opt_param_t *params)
{
    /* Remaining bytes in option block */
    int          optlen     = (int) (params->optend - params->optidx);

    /* Done with this block? Do terminate and re-enter ordinary forwarding */
    if (optlen <= 0)
        return ipnet_ip4_opt_done(params);

    /* Lets find the next valid option */
    switch (opt->flag_class_num)
    {
    case IP_IPOPT_END:
        /* Explicit option end, do destination cache forwarding */
        return ipnet_ip4_opt_done(params);
    case IP_IPOPT_NOOP:
        /* NOOP special case, just forward one byte */
        params->optidx++;
        return ipnet_ip4_opt_input((void *)&params->pkt->data[params->optidx], params);
    default:
        /* Do sanity */
        if (optlen < 2)
            /*
             * Length field did not fit
             */
            return ipnet_ip4_opt_icmp_param_prob(opt, 0, params);

        if (opt->len < 2 /* Option length too small? */
            || (opt->len) > optlen) /* Option length too big? */
        {
            /*
             * Set pointer to length field.
             */
            return ipnet_ip4_opt_icmp_param_prob(opt, 1, params);
        }

        /* Go */
        return ipnet_ip4_opts[opt->flag_class_num](opt, params);
    }
}


IP_INLINE int
ipnet_ip4_opt_next(Ipnet_pkt_ip_opt *opt, Ipnet_ip4_opt_param_t *params)
{
    params->optidx += opt->len;
    return ipnet_ip4_opt_input((void *)&params->pkt->data[params->optidx], params);
}


IP_STATIC int
ipnet_ip4_opt_rr_rx(Ipnet_pkt_ip_opt *opt, Ipnet_ip4_opt_param_t *params)
{
    char *optd = (char *)opt;

    if (params->dst->to_type == IPNET_ADDR_TYPE_NOT_LOCAL
        || params->dst->to_type == IPNET_ADDR_TYPE_UNICAST)
    {
        /* Destined for us */
        /* Verify some parameters */
        if (optd[2] < 4)
            return ipnet_ip4_opt_icmp_param_prob(opt, 2, params);

        if (optd[2] <= opt->len)
        {
            Ip_u32 ipaddr_n = IP_INADDR_ANY;
            Ipnet_netif *netif = params->dst->neigh->netif;

            /* Enough space? */
            if (optd[2] + 3 > opt->len)
                return ipnet_ip4_opt_icmp_param_prob(opt, 2, params);

            if (IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_LOOPBACK))
                ipaddr_n = params->dst->flow_spec.to.in.s_addr;
            else if (netif->inet4_addr_list != IP_NULL)
                ipaddr_n = netif->inet4_addr_list->ipaddr_n;

            if (ipaddr_n != IP_INADDR_ANY)
            {
                /* Store netifs primary interface address */
                IP_SET_32ON8((optd + optd[2] - 1), ipaddr_n);

                /* Advance offset pointer */
                optd[2] = (char) (optd[2] + 4);

                /* Indicate checksum update required */
                params->need_cksum = IP_TRUE;
            }
            /* Continue with processing this frame - this option is done */
        }
        else
        {
            /*
             * RFC791, page 20:
             *   If the route data area is already full (the pointer exceeds the
             *   length) the datagram is forwarded without inserting the address
             *   into the recorded route.  If there is some room but not enough
             *   room for a full address to be inserted, the original datagram is
             *   considered to be in error and is discarded.  In either case an
             *   ICMP parameter problem message may be sent to the source
             *   host [3].
             */
            IPCOM_PKT_ADD_REF(params->pkt);
            (void)ipnet_ip4_opt_icmp_param_prob(opt, 2, params);
        }
    }

    /* Do next */
    return ipnet_ip4_opt_next(opt, params);
}


/*
 *===========================================================================
 *                          ipnet_ip4_opt_srr_rx
 *===========================================================================
 * Description: Processes source route option on received packets.
 * Parameters:  opt - pointer to option
 *              params - additional information
 * Returns:
 *
 */
IP_STATIC int
ipnet_ip4_opt_srr_rx(Ipnet_pkt_ip_opt *opt, Ipnet_ip4_opt_param_t *params)
{
    Ipnet_data *net = params->dst->net;
    char       *optd = (char *)opt;

    if (IP_FALSE != params->dst->ingress_netif->conf.inet.accept_source_route)
    {
        /* Not to us? */
        if (params->dst->to_type == IPNET_ADDR_TYPE_UNICAST)
        {
            /* Destined for us */
            /* Verify some parameters */
            if (optd[2] < 4)
                return ipnet_ip4_opt_icmp_param_prob(opt, 2, params);

            if (optd[2] <= opt->len)
            {
                Ipnet_flow_spec  flow_spec;
                Ipnet_dst_cache *dst;
                Ip_u32           ndst;
                Ipnet_netif      *netif = IP_NULL;

                /* Enough space? */
                if (optd[2] + 3 > opt->len)
                    return ipnet_ip4_opt_icmp_param_prob(opt, 2, params);

                /* Process next entry */
                ndst = IP_GET_32ON8(optd + optd[2] -1);

                flow_spec = params->dst->flow_spec;
                flow_spec.to.in.s_addr = ndst;

                /* Time to resolve the next hop */
                dst = ipnet_dst_cache_get(net, &flow_spec);
                if (IP_UNLIKELY(dst == IP_NULL))
                {
                    int ret;
                    /*
                     * This is a new flow. Lets create a destination cache entry
                     * for it. This is the point where we decide if this flow
                     * should be delivered locally, forwarded or discarded
                     * (martian addresses, impossible source address, etc).
                     */
                    ret = ipnet_dst_cache_new(net,
                                              &flow_spec,
                                              ipnet_ip4_dst_cache_rx_ctor,
                                              &dst);

                    /* Failed to route? */
                    if (ret < 0)
                        return ipnet_ip4_opt_icmp_error(IPNET_ICMP4_TYPE_DST_UNREACHABLE, IPNET_ICMP4_CODE_DST_SRCFAIL, params);
                }

                /* New destination */
                params->dst = dst;

                if (opt->flag_class_num == IP_IPOPT_SSRR)
                {
                    Ipnet_ip4_addr_entry *addr = ipnet_ip4_get_addr_entry(IP_GET_32ON8(params->ip_hdr->dst), params->pkt->vr_index, IP_NULL);
                    if (IP_NULL != addr)
                        netif = addr->netif;
                }

                /* Set nexthop value in ip header */
                IP_SET_32ON8(&params->ip_hdr->dst, ndst);


                if (IP_NULL == netif)
                    netif = params->dst->neigh->netif;

                if (netif->inet4_addr_list == IP_NULL)
                    return ipnet_ip4_opt_icmp_error(IPNET_ICMP4_TYPE_DST_UNREACHABLE, IPNET_ICMP4_CODE_DST_SRCFAIL, params);


                /* Store netifs primary interface address */
                if (IP_BIT_ISSET(netif->ipcom.flags, IP_IFF_LOOPBACK))
                    IP_SET_32ON16((optd + optd[2] - 1), params->dst->flow_spec.to.in.s_addr);
                else
                    IP_SET_32ON8((optd + optd[2] - 1), netif->inet4_addr_list->ipaddr_n);

                /* Advance offset pointer */
                optd[2] = (char) (optd[2] + 4);

                /* Indicate checksum update required */
                params->need_cksum = IP_TRUE;

                /* Is the next field also to us? */
                if (dst->to_type == IPNET_ADDR_TYPE_UNICAST)
                    return ipnet_ip4_opt_srr_rx(opt, params);
                /* Is it a valid nexthop? dont do multicast & broadcasts */
                else if (dst->to_type != IPNET_ADDR_TYPE_NOT_LOCAL)
                    return ipnet_ip4_opt_icmp_error(IPNET_ICMP4_TYPE_DST_UNREACHABLE, IPNET_ICMP4_CODE_DST_SRCFAIL, params);

                /* Continue with processing this frame - this option is done */
            }
            else
            {
                /* No more space - ordinary routing */
            }
        }
        else
        {
            /* Strict? */
            if (opt->flag_class_num == IP_IPOPT_SSRR)
                return ipnet_ip4_opt_icmp_error(IPNET_ICMP4_TYPE_DST_UNREACHABLE, IPNET_ICMP4_CODE_DST_SRCFAIL, params);
        }
    }
    else
    {
        /* Src Routing not allowed */
        return ipnet_ip4_opt_icmp_error(IPNET_ICMP4_TYPE_DST_UNREACHABLE, IPNET_ICMP4_CODE_DST_SRCFAIL, params);
    }

    /* Do next */
    return ipnet_ip4_opt_next(opt, params);
}


IP_STATIC int
ipnet_ip4_opt_ra_rx(Ipnet_pkt_ip_opt *opt, Ipnet_ip4_opt_param_t *params)
{
    /* Router Advertisement Input */
    if (IP_BIT_ISSET(params->seen_options, 1u << IP_IPOPT_NUMBER(opt->flag_class_num)))
        return ipnet_ip4_opt_icmp_param_prob(opt, 0, params);

    IP_BIT_SET(params->seen_options, 1u << IP_IPOPT_NUMBER(opt->flag_class_num));

    /* Not to us? */
    if (params->dst->to_type == IPNET_ADDR_TYPE_NOT_LOCAL)
    {
        Ipnet_ip4_layer_info *ip4_info = IPNET_IP4_GET_LAYER_INFO(params->pkt);

        /*
         * Move parameter pointer to the RFC2113 specifies a
         * single value for this option:
         * 0 - Router shall examine packet all other values
         * are reserverd.
         */
        if (opt->len != (Ip_u8)4 || opt->data[0] != 0 || opt->data[1] != 0)
            return ipnet_ip4_opt_icmp_param_prob(opt, 2, params);

        /*
         * IP-datagram contains the router alert option
         */
        IP_BIT_SET(ip4_info->flags, IPNET_IP4_OPF_ROUTER_ALERT);
    }

    /*
     * else: RFC 2113 states that hosts should ignore this
     * option.
     */


    /* Do next */
    return ipnet_ip4_opt_next(opt, params);
}


/*
 *===========================================================================
 *                      ipnet_ip4_process_ts_opt
 *===========================================================================
 * Description: Processes the timestamp option
 * Parameters:  opt - pointer to the option
 *              params - context information
 * Returns:     0 = success, <0 = error code.
 *
 */
IP_STATIC int
ipnet_ip4_opt_ts_rx(Ipnet_pkt_ip_opt *opt, Ipnet_ip4_opt_param_t *params)
{
    int ret;

    if (IP_BIT_ISSET(params->seen_options, 1u << IP_IPOPT_NUMBER(opt->flag_class_num)))
        return ipnet_ip4_opt_icmp_param_prob(opt, 0, params);

    IP_BIT_SET(params->seen_options, 1u << IP_IPOPT_NUMBER(opt->flag_class_num));

    if (opt->len < 4)
        return ipnet_ip4_opt_icmp_param_prob(opt, 1, params);

    /* Process option */
    ret = ipnet_ip4_process_ts_opt((Ipnet_pkt_ip_opt_timestamp *) opt,
                                   (Ip_u32 *) params->ip_hdr->dst,
                                   params->pkt,
                                   IP_TRUE);
    if (ret)
        return ipnet_ip4_opt_icmp_param_prob(opt, (Ip_u8)(-IP_ERRNO_ENOSPC == ret? 3 : 2), params);

    /* Must update checksum */
    params->need_cksum = IP_TRUE;

    /**/
    return ipnet_ip4_opt_next(opt, params);
}


IP_STATIC int
ipnet_ip4_opt_unsupported_rx(Ipnet_pkt_ip_opt *opt, Ipnet_ip4_opt_param_t *params)
{
    return ipnet_ip4_opt_next(opt, params);
}


IP_STATIC void
ipnet_ip4_reg_opt_rx(Ip_u8 opt, Ipnet_ip4_opt_rx_func func)
{
    ipnet_ip4_opts[opt] = func;
}

/*===========================================================================    
  *                  ipnet_ip4_multiple_srr_opt_check                       
  *==========================================================================   
  * Description:  Check for whether multiple Source route or Record route 
  *               options exist  
  * Parameters:          
  *                      params - IP options contained
  * Returns:     
  *                      0 = success, <0 = error code.           
  */
IP_STATIC int
ipnet_ip4_multiple_srr_opt_check(Ipnet_ip4_opt_param_t *params)
{
    int srr_opt_count = 0;
    int rr_opt_count = 0;
    Ip_size_t optidx = params->optidx;
    Ipnet_pkt_ip_opt *opt = IP_NULL;

    /*IP option is blank, no need do this check.  Do terminate and enter forwarding process*/
    if (params->optsize <= 0)
        return IPCOM_SUCCESS;
    /*Total option len is too short*/
    if (params->optsize < 2)
        return ipnet_ip4_opt_icmp_param_prob((void *)&(params->pkt->data[params->optidx]), 0, params);
    while(optidx < params->optend)
    {
        opt = (Ipnet_pkt_ip_opt*)&(params->pkt->data[optidx]);
        ip_assert(opt != IP_NULL);
        switch (opt->flag_class_num)
        {
        case IP_IPOPT_LSRR:
        case IP_IPOPT_SSRR:
            if (srr_opt_count >= 1)
            {
                /* RFC1812 s5.2.4.1 IP Destination Address:
                    It is an error for more than one source route option to appear in a
                    datagram.  If it receives such a datagram, it SHOULD discard the
                    packet and reply with an ICMP Parameter Problem message whose pointer
                    points at the beginning of the second source route option. */
                return ipnet_ip4_opt_icmp_param_prob(opt, 0, params);
            }
            /*option len is too short or too long*/
            if (opt->len < 2 || (opt->len) > (params->optend - optidx))
                goto Errlen;
            srr_opt_count++;
            optidx += opt->len;
            break;
        case IP_IPOPT_RR:
            if (rr_opt_count >= 1)
            {
                /*RFC791 s3.1 Page 21:
                    Record Route option appears at most once in a datagram.*/
                return ipnet_ip4_opt_icmp_param_prob(opt, 0, params);
            }
            if (opt->len < 2 || (opt->len) > (params->optend - optidx))
                goto Errlen;
            rr_opt_count++;
            optidx += opt->len;
            break;
        case IP_IPOPT_NOOP:
            optidx++;
            break;
        case IP_IPOPT_END:
            return IPCOM_SUCCESS;
        default:
            if (opt->len < 2 || (opt->len) > (params->optsize - optidx))
                goto Errlen;
            optidx += opt->len;
            break;
        }
    }
    return IPCOM_SUCCESS;
 Errlen:
    return ipnet_ip4_opt_icmp_param_prob(opt, 1, params);
}

IP_FASTTEXT IP_GLOBAL int
ipnet_ip4_rx(Ipnet_dst_cache *dst, Ipcom_pkt *pkt, Ipnet_pkt_ip *iphdr)
{
    Ipnet_ip4_layer_info ip4_info;
    Ip_size_t            opt_len;

    IPNET_IP4_SET_LAYER_INFO(pkt, &ip4_info);
    ip4_info.proto   = iphdr->p;
    ip4_info.ttl     = iphdr->ttl;
    ip4_info.flags   = 0;
    ip4_info.id      = 0;
    ip4_info.nexthop = IP_NULL;
    ip4_info.opts    = IP_NULL;

    if (0 < (opt_len = ipnet_ip4_get_opts_octet_len(iphdr)))
    {
        Ipnet_ip4_opt_param_t   params;
        int ret;

        /* Store */
        ipcom_memcpy(params.options, iphdr + 1, opt_len);
        params.optsize      = opt_len;
        params.optidx       = (Ip_size_t)pkt->ipstart + IPNET_IP_HDR_SIZE;
        params.optend       = params.optidx + opt_len;
        params.seen_options = 0;
        params.need_cksum   = IP_FALSE;
        params.pkt          = pkt;
        params.dst          = dst;
        params.ip_hdr       = iphdr;

        /*
        RFC1812 s5.2.4.1 IP Destination Address
                
                   It is an error for more than one source route option to appear in a
                   datagram.  If it receives such a datagram, it SHOULD discard the
                   packet and reply with an ICMP Parameter Problem message whose pointer
                   points at the beginning of the second source route option.

        RFC791 s3.1 Page 21:
                   Record Route option appears at most once in a datagram.
        */
        if((ret = ipnet_ip4_multiple_srr_opt_check(&params))!= IPCOM_SUCCESS)
            return ret;
        return ipnet_ip4_opt_input((void *)&params.pkt->data[params.optidx], &params);
    }

    /*
     * Deliver packet to the appropriate transport layer handler.
     */
    return ipnet_dst_cache_rx(dst, pkt);
}


/*
 *===========================================================================
 *                    ipnet_ip4_input
 *===========================================================================
 * Description: Handler for received IPv4 packets. This function will
 *              only perform sanity check on the header.
 * Parameters:  pkt - Received IPv4 packet. (pkt->start is offset to IPv4 header)
 * Returns:     0 = success, <0 = error code.
 *
 */
IP_FASTTEXT IP_GLOBAL int
ipnet_ip4_input(Ipnet_netif *netif, Ipcom_pkt *pkt)
{
    Ipnet_pkt_ip    *iphdr;
    int              ip_datagram_len;
    int              iphdr_len;
    int              ret = -IP_ERRNO_EINVAL;
    Ipnet_flow_spec  flow_spec;
    Ipnet_dst_cache *dst;
    Ipnet_data      *net = ipnet_pkt_get_stack_instance(pkt);
    IPCOM_WV_DECLARE_VARS;

    IPCOM_PKT_TRACE(pkt, IPCOM_PKT_ID_IP4_INPUT);

    ip_assert(netif != IP_NULL);
    ip_assert(pkt != IP_NULL);
    ip_assert(pkt->data != IP_NULL);
    ip_assert(pkt->end <= pkt->maxlen);
    ip_assert(pkt->start <= pkt->end);

    IPCOM_WV_MARKER_1 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_VERBOSE,
                       1, 28, IPCOM_WV_NETDEVENT_START,
                       ipnet_ip4_input,
                       IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
    IPNET_STATS(net, ip4_input++);
    IPCOM_MIB2(net, ipInReceives++);
    IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCInReceives, 1);
    IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCInReceives, 1, netif, pkt->stack_idx);
    /* coverity[check_return] */
    IPCOM_MIB2_SYSWI_U64_ADD(net, v4, ipSystemStatsHCInOctets, ipcom_pkt_get_length(pkt));
    /* coverity[check_return] */
    IPCOM_MIB2_PERIF_U64_ADD(v4, ipIfStatsHCInOctets, ipcom_pkt_get_length(pkt), netif, pkt->stack_idx);

    IP_BIT_SET(pkt->flags, IPCOM_PKT_FLAG_IPV4);
    IP_BIT_CLR(pkt->flags, IPCOM_PKT_FLAG_IPV6);
    pkt->ipstart = pkt->start;

    if (IP_UNLIKELY(IP_BIT_ISSET(pkt->flags, IPCOM_PKT_FLAG_LINK_OTHER)))
        /*
         * Do not process packets that was sent to a link layer
         * unicast address that is not ours, AF_PACKET sockets will
         * get this packet if the interface is promiscuous mode
         */
        goto errout;


#ifdef IPROHC
    /*
     * Restore an uncompressed IP header if it has been compressed
     * with robust header compression.
     */
    if (iprohc.opened)
    {
        ret = iprohc_input_hook(&netif->ipcom, pkt);
        if (ret != IPCOM_SUCCESS)
        {
            /* Decompress fails, discard the packet */
            IPCOM_LOG1(WARNING,
                       "Discarding rcv'ed IPv4 datagram on %s, ROHC failed.",
                       netif->ipcom.name);
            ret = IPNET_ERRNO(EROHC);
            IPCOM_WV_SET_VARS(28, IPCOM_WV_NETD_INVAL);
            goto errout;
        }
    }
#endif /* IPROHC */

    /*
     * Check that the packet is large enough to contain an IP header.
     * No need to use ipcom_pkt_get_length() here since the stack
     * requres that all headers are located in the first packet in
     * ingress packets.
     */
    if (IP_UNLIKELY(pkt->end - pkt->start < IPNET_IP_HDR_SIZE))
    {
        IPCOM_WV_SET_VARS(29, IPCOM_WV_NETD_BADHLEN);
        IPNET_STATS(net, ip4_input_hdr_trunc++);
        goto errout;
    }

    /*
     * Check that the protocol is 4.
     */
    iphdr = ipcom_pkt_get_iphdr(pkt);
    if (IP_UNLIKELY(IPNET_IP4_GET_VERSION(iphdr) != 4))
    {
        IPCOM_WV_SET_VARS(30, IPCOM_WV_NETD_BADVERS);
        goto errout;
    }

    /*
     * Packet is large enough, to at least, hold an IP header. Read
     * the header & payload length fields. Verify that the packet
     * length is consisten with the payload length in the IP header.
     */
    iphdr_len = IPNET_IP4_GET_HDR_OCTET_LEN(iphdr);
    ip_datagram_len = ip_ntohs(iphdr->len);
    if (IP_UNLIKELY(iphdr_len < IPNET_IP_HDR_SIZE)
        || IP_UNLIKELY(ip_datagram_len < iphdr_len))
    {
        /*
         * Bad packet, bad header size or total length < size of header.
         */
        IPCOM_WV_SET_VARS(31, IPCOM_WV_NETD_BADLEN);
        goto errout;
    }

    if (IP_UNLIKELY(ipcom_pkt_get_length(pkt) != ip_datagram_len))
    {
        if (ipcom_pkt_get_length(pkt) < ip_datagram_len)
        {
            /*
             * Either a bogus packet or the packet was truncated at
             * some point
             */
            IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsInTruncatedPkts, 1);
            IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsInTruncatedPkts, 1, netif, pkt->stack_idx);
            IPCOM_WV_SET_VARS(32, IPCOM_WV_NETD_BADLEN);
            goto errout_mib_done;
        }

        (void)ipcom_pkt_trim_tail(pkt, ipcom_pkt_get_length(pkt)-ip_datagram_len);

#ifdef IPCOM_USE_HW_CHECKSUM_RX
        /*
         * The hardware calculated checksum has included padding
         * so it cannot be used, revert back to software checksumming
         */
        pkt->chk = 0;
        IP_BIT_CLR(pkt->flags, IPCOM_PKT_FLAG_TL_CHECKSUM);
#endif
    }

    /*
     * Verify that the IP header checksum is correct.
     */
    if (IP_UNLIKELY(ipcom_in_checksum(iphdr, (Ip_size_t)iphdr_len) != 0))
    {
        IPCOM_WV_SET_VARS(34, IPCOM_WV_NETD_BADSUM);
        IPNET_STATS(net, ip4_input_iph_badchksum++);
        goto errout;
    }

    
    /*
     * The IP headers does not contain any obvious errors. Time to get
     * the receive handler for this packet.
     */
    ipnet_ip4_flow_spec_from_pkt(&flow_spec, pkt, iphdr, IP_TRUE);


    dst = ipnet_dst_cache_get(net, &flow_spec);


    if (IP_UNLIKELY(dst == IP_NULL))
    {
        /*
         * This is a new flow. Lets create a destination cache entry
         * for it. This is the point where we decide if this flow
         * should be delivered locally, forwarded or discarded
         * (martian addresses, impossible source address, etc).
         */
	
        ret = ipnet_dst_cache_new(net,
                                  &flow_spec,
                                  ipnet_ip4_dst_cache_rx_ctor,
                                  &dst);
        if (ret < 0)
        {
            switch (-ret)
            {
            case IP_ERRNO_EHOSTUNREACH:
            case IP_ERRNO_ENETUNREACH:
            case IP_ERRNO_EACCES:
                ipnet_ip4_dst_unreachable(pkt, -ret);
                break;
            default:
                IPCOM_WV_SET_VARS(35, IPCOM_WV_NETD_NOBUFS);
                break;
            }
            goto errout_mib_done;
        }
    }

    /*
     * Deliver packet to the appropriate transport layer handler.
     */
    return ipnet_ip4_rx(dst, pkt, iphdr);

 errout:
    /*
     * This IP datagram failed basic sanity testing.
     */
    IPCOM_MIB2(net, ipInHdrErrors++);
    IPCOM_MIB2_SYSWI_U32_ADD(net, v4, ipSystemStatsInHdrErrors, 1);
    IPCOM_MIB2_PERIF_U32_ADD(v4, ipIfStatsInHdrErrors, 1, netif, pkt->stack_idx);

 errout_mib_done:
    IPCOM_WV_EVENT_2 (IPCOM_WV_NETD_IP4_DATAPATH_EVENT, IPCOM_WV_NETD_WARNING,
                      1, IPCOM_WV_VAR1, IPCOM_WV_NETDEVENT_WARNING, IPCOM_WV_NETD_RECV,
                      ipnet_ip4_input, IPCOM_WV_VAR2,
                      IPCOM_WV_IPNET_IP4_MODULE, IPCOM_WV_NETD_IP4);
    IPNET_STATS(net, ip4_input_err++);
    ipcom_pkt_free(pkt);

    return ret;
}


/*
 *===========================================================================
 *                         ipnet_ip4_transport_rx
 *===========================================================================
 * Description: Delivers a packet to an IP-protocol handler
 * Parameters:  dst - destination cache entry for the packet
 *              pkt - a packet buffer
 *              proto - IP-protocol for the packet.
 * Returns:
 *
 */
IP_GLOBAL void
ipnet_ip4_transport_rx(Ipnet_dst_cache *dst, Ipcom_pkt *pkt, Ip_u8 proto)
{
    ipnet_ip4_transport_layer_rx[proto](dst, pkt);
}


/*
 *===========================================================================
 *                    ipnet_ip4_get_mss
 *===========================================================================
 * Description: Returns the MSS for the connected socket 'sock'.
 * Parameters:  sock - The TCP socket to calculate MSS for.
 *              is_link_local - will contain IP_FALSE if the peer is only
 *                              reachable through a gateway.
 * Returns:     The MSS.
 *
 */
#ifdef IPTCP
IP_GLOBAL Ip_u32
ipnet_ip4_get_mss(Ipnet_socket *sock, Ip_bool *is_link_local)
{
    Ip_u32            mtu;
    Ip_u32            mss;
    Ipnet_flow_spec   flow_spec;
    Ipnet_dst_cache  *dst = IP_NULL;
    Ipnet_data       *net = ipnet(ipnet_this());

    if (ipnet_flow_spec_from_sock(&flow_spec,
                                  sock,
                                  IP_NULL,
                                  ipnet_ip4_flow_spec_from_sock) == 0)
    {
        dst = ipnet_dst_cache_get(net, &flow_spec);
        if (dst == IP_NULL
            && ipnet_dst_cache_new(net,
                                   &flow_spec,
                                   ipnet_ip4_dst_cache_local_tx_ctor,
                                   &dst) < 0)
            dst = IP_NULL;
    }

    if (dst == IP_NULL)
    {
        mtu = ipnet_conf_ip4_min_mtu;
        *is_link_local = IP_FALSE;
    }
    else
    {
        mtu = dst->path_mtu;
        *is_link_local = (dst->flow_spec.to.in.s_addr
                          == dst->neigh->addr.in.s_addr);
    }

#ifdef IPIPSEC2
    {
        Ipipsec_param    ipsec_param;

        ipsec_param.key.src.in.s_addr = sock->ip4->saddr_n;
        ipsec_param.key.dst.in.s_addr = sock->ip4->daddr_n;
        ipsec_param.key.proto  = (Ip_u8) sock->proto;
        ipsec_param.key.domain = IP_AF_INET;
        ipsec_param.key.ports.udptcp_srcdst_n[0] = ip_htons(sock->sport);
        ipsec_param.key.ports.udptcp_srcdst_n[1] = ip_htons(sock->dport);

        mtu -= ipipsec_output_hdrspace(&ipsec_param);
    }
#endif /* IPIPSEC2 */

    mss = mtu - sock->max_hdrspace;
    return IP_MIN((Ip_u32) sock->recv_max_bytes, mss);
}
#endif /* IPTCP */


/*
 ****************************************************************************
 * 11                   PUBLIC FUNCTIONS
 ****************************************************************************
 */
#else
int ipnet_ip4_empty_file;
#endif /* IPCOM_USE_INET */


/*
 ****************************************************************************
 *                      END OF FILE
 ****************************************************************************
 */
