/**
 * \addtogroup uip6
 * @{
 */
/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
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
 *
 * This file is part of the Contiki operating system.
 *
 */
/**
 * \file
 *         ICMP6 I/O for RPL control messages.
 *
 * \author Joakim Eriksson <joakime@sics.se>, Nicolas Tsiftes <nvt@sics.se>
 * Contributors: Niclas Finne <nfi@sics.se>, Joel Hoglund <joel@sics.se>,
 *               Mathieu Pouillot <m.pouillot@watteco.com>
 *               George Oikonomou <oikonomou@users.sourceforge.net> (multicast)
 */

#include "net/ip/tcpip.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-nd6.h"
#include "net/ipv6/uip-icmp6.h"
#include "net/rpl/rpl-private.h"
#include "net/packetbuf.h"
#include "net/ipv6/multicast/uip-mcast6.h"

#include <limits.h>
#include <string.h>

//#define DEBUG DEBUG_NONE
#define DEBUG DEBUG_FLAG

#include "net/ip/uip-debug.h"

#if UIP_CONF_IPV6
/*---------------------------------------------------------------------------*/
#define RPL_DIO_GROUNDED                 0x80
#define RPL_DIO_MOP_SHIFT                3
#define RPL_DIO_MOP_MASK                 0x3c
#define RPL_DIO_PREFERENCE_MASK          0x07

#define UIP_IP_BUF       ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_ICMP_BUF     ((struct uip_icmp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
#define UIP_ICMP_PAYLOAD ((unsigned char *)&uip_buf[uip_l2_l3_icmp_hdr_len])
/*---------------------------------------------------------------------------*/
static void dis_input(void);
static void dio_input(void);
static void dao_input(void);
static void dao_ack_input(void);

/* some debug callbacks useful when debugging RPL networks */
#ifdef RPL_DEBUG_DIO_INPUT
void RPL_DEBUG_DIO_INPUT(uip_ipaddr_t *, rpl_dio_t *);
#endif

#ifdef RPL_DEBUG_DAO_OUTPUT
void RPL_DEBUG_DAO_OUTPUT(rpl_parent_t *);
#endif

#if RPL_WHITE_LIST
/* 保存DAO数据,等到接收DAO ACK需要使用 */
uip_ipaddr_t g_prefix;
uip_ipaddr_t g_dao_sender_addr;
uint8_t g_prefixlen = 0;
uint16_t g_sequence = 0;
uint8_t g_instance_id;
uint8_t g_lifetime;
uip_ds6_nbr_t *g_nbr;

/* 白名单按钮 */
#if RPL_ROLE_ROUTER
uint8_t white_list_button = 1; //1可加入, 路由暂时没有按钮, 暂时固定为1
#else
uint8_t white_list_button = 0; //1可加入
#endif

uint8_t dis_atomic = 0; //收到dis回复dio的原子操作
struct ctimer dis_atomic_timer;
#endif

static uint8_t dao_sequence = RPL_LOLLIPOP_INIT;

extern rpl_of_t RPL_OF;

#if RPL_CONF_MULTICAST
static uip_mcast6_route_t *mcast_group;
#endif
/*---------------------------------------------------------------------------*/
/* Initialise RPL ICMPv6 message handlers */
UIP_ICMP6_HANDLER(dis_handler, ICMP6_RPL, RPL_CODE_DIS, dis_input);
UIP_ICMP6_HANDLER(dio_handler, ICMP6_RPL, RPL_CODE_DIO, dio_input);
UIP_ICMP6_HANDLER(dao_handler, ICMP6_RPL, RPL_CODE_DAO, dao_input);
UIP_ICMP6_HANDLER(dao_ack_handler, ICMP6_RPL, RPL_CODE_DAO_ACK, dao_ack_input);
/*---------------------------------------------------------------------------*/
static int
get_global_addr(uip_ipaddr_t *addr)
{
  int i;
  int state;

  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      if(!uip_is_addr_link_local(&uip_ds6_if.addr_list[i].ipaddr)) {
        memcpy(addr, &uip_ds6_if.addr_list[i].ipaddr, sizeof(uip_ipaddr_t));
        return 1;
      }
    }
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
static uint32_t
get32(uint8_t *buffer, int pos)
{
  return (uint32_t)buffer[pos] << 24 | (uint32_t)buffer[pos + 1] << 16 |
         (uint32_t)buffer[pos + 2] << 8 | buffer[pos + 3];
}
/*---------------------------------------------------------------------------*/
static void
set32(uint8_t *buffer, int pos, uint32_t value)
{
  buffer[pos++] = value >> 24;
  buffer[pos++] = (value >> 16) & 0xff;
  buffer[pos++] = (value >> 8) & 0xff;
  buffer[pos++] = value & 0xff;
}
/*---------------------------------------------------------------------------*/
static uint16_t
get16(uint8_t *buffer, int pos)
{
  return (uint16_t)buffer[pos] << 8 | buffer[pos + 1];
}
/*---------------------------------------------------------------------------*/
static void
set16(uint8_t *buffer, int pos, uint16_t value)
{
  buffer[pos++] = value >> 8;
  buffer[pos++] = value & 0xff;
}
/*---------------------------------------------------------------------------*/
#if RPL_WHITE_LIST && !RPL_LEAF_ONLY
void handle_dis_atomic_timer(void *ptr)
{
    dis_atomic = 0;
    return;
}
#endif
/*---------------------------------------------------------------------------*/
static void
dis_input(void)
{
  rpl_instance_t *instance;
  rpl_instance_t *end;
  int pos = 0;

  /* DAG Information Solicitation */
  PRINTF("RPL: Received a DIS from ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF("\n");

  for(instance = &instance_table[0], end = instance + RPL_MAX_INSTANCES;
      instance < end; ++instance) {
#if RPL_WHITE_LIST
    //uip_ds6_nbr_t *ds6_nbr = uip_ds6_nbr_lookup(&UIP_IP_BUF->srcipaddr);
    //const uip_lladdr_t *lladdr = uip_ds6_nbr_get_ll(ds6_nbr);
    //linkaddr_t packetbuf_addr(PACKETBUF_ADDR_SENDER)
    /* 必须保证有父节点,其次在白名单中或者按钮被按下 */
#if RPL_LEAF_ONLY
    if(instance->used == 1 && instance->dao_ack == 1) {
#else
    pos = mac_in_white_list((const uip_lladdr_t *)packetbuf_addr(PACKETBUF_ADDR_SENDER));
    if(instance->used == 1 && instance->dao_ack == 1 
         && ((-1 != pos && mac_is_nbr(pos)) || 1 == white_list_button)) {
#endif
#else
    if(instance->used == 1) {
#endif
#if RPL_LEAF_ONLY
      if(!uip_is_addr_mcast(&UIP_IP_BUF->destipaddr)) {
	PRINTF("RPL: LEAF ONLY Multicast DIS will NOT reset DIO timer\n");
#else /* !RPL_LEAF_ONLY */
      if(uip_is_addr_mcast(&UIP_IP_BUF->destipaddr)) {
        PRINTF("RPL: Multicast DIS => reset DIO timer\n");
#if RPL_WHITE_LIST
        if (1 == dis_atomic)
        {
            PRINTF("Another dis recv within 2s \n");
            continue;
        }
        dis_atomic = 1;
        ctimer_set(&dis_atomic_timer, CLOCK_SECOND * 2, &handle_dis_atomic_timer, NULL);
        if (1 == white_list_button) {
            /* 按钮被按下,收到到dis包,加入nbr */
            uip_ds6_nbr_t *nbr;
            if((nbr = uip_ds6_nbr_lookup(&UIP_IP_BUF->srcipaddr)) == NULL) {
                if((nbr = uip_ds6_nbr_add(&UIP_IP_BUF->srcipaddr, 
                              (uip_lladdr_t *)packetbuf_addr(PACKETBUF_ADDR_SENDER),
                              0, NBR_REACHABLE)) != NULL) {
                  /* set reachable timer */
                  stimer_set(&nbr->reachable, UIP_ND6_REACHABLE_TIME / 1000);
                  PRINTF("RPL read conf: Neighbor added to neighbor cache ");
                  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
                  PRINTF(", ");
                  PRINTLLADDR((uip_lladdr_t *)packetbuf_addr(PACKETBUF_ADDR_SENDER));
                  PRINTF("\n");
                }
            }
        }
        dio_output(instance, &UIP_IP_BUF->srcipaddr);
#else
        rpl_reset_dio_timer(instance);
#endif
      } else {
#endif /* !RPL_LEAF_ONLY */
        PRINTF("RPL: Unicast DIS, reply to sender\n");
        dio_output(instance, &UIP_IP_BUF->srcipaddr);
      }
    }
  }
  uip_len = 0;
}
/*---------------------------------------------------------------------------*/
void
dis_output(uip_ipaddr_t *addr)
{
  unsigned char *buffer;
  uip_ipaddr_t tmpaddr;

  /*
   * DAG Information Solicitation  - 2 bytes reserved
   *      0                   1                   2
   *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
   *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *     |     Flags     |   Reserved    |   Option(s)...
   *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */

  buffer = UIP_ICMP_PAYLOAD;
  buffer[0] = buffer[1] = 0;

  if(addr == NULL) {
    uip_create_linklocal_rplnodes_mcast(&tmpaddr);
    addr = &tmpaddr;
  }

  PRINTF("RPL: Sending a DIS to ");
  PRINT6ADDR(addr);
  PRINTF("\n");

  uip_icmp6_send(addr, ICMP6_RPL, RPL_CODE_DIS, 2);
}
/*---------------------------------------------------------------------------*/
static void
dio_input(void)
{
  unsigned char *buffer;
  uint8_t buffer_length;
  rpl_dio_t dio;
  uint8_t subopt_type;
  int i;
  int len;
  uip_ipaddr_t from;
  uip_ds6_nbr_t *nbr;

  memset(&dio, 0, sizeof(dio));

  /* Set default values in case the DIO configuration option is missing. */
  dio.dag_intdoubl = RPL_DIO_INTERVAL_DOUBLINGS;
  dio.dag_intmin = RPL_DIO_INTERVAL_MIN;
  dio.dag_redund = RPL_DIO_REDUNDANCY;
  dio.dag_min_hoprankinc = RPL_MIN_HOPRANKINC;
  dio.dag_max_rankinc = RPL_MAX_RANKINC;
  dio.ocp = RPL_OF.ocp;
  dio.default_lifetime = RPL_DEFAULT_LIFETIME;
  dio.lifetime_unit = RPL_DEFAULT_LIFETIME_UNIT;

  uip_ipaddr_copy(&from, &UIP_IP_BUF->srcipaddr);

  /* DAG Information Object */
  PRINTF("RPL: Received a DIO from ");
  PRINT6ADDR(&from);
  PRINTF("\n");

  if((nbr = uip_ds6_nbr_lookup(&from)) == NULL) {
    if((nbr = uip_ds6_nbr_add(&from, 
                (uip_lladdr_t *) packetbuf_addr(PACKETBUF_ADDR_SENDER),
                0, NBR_REACHABLE)) != NULL) {
      /* set reachable timer */
      stimer_set(&nbr->reachable, UIP_ND6_REACHABLE_TIME / 1000);
      PRINTF("RPL: Neighbor added to neighbor cache ");
      PRINT6ADDR(&from);
      PRINTF(", ");
      PRINTLLADDR((uip_lladdr_t *)packetbuf_addr(PACKETBUF_ADDR_SENDER));
      PRINTF("\n");
    } else {
      PRINTF("RPL: Out of memory, dropping DIO from ");
      PRINT6ADDR(&from);
      PRINTF(", ");
      PRINTLLADDR((uip_lladdr_t *)packetbuf_addr(PACKETBUF_ADDR_SENDER));
      PRINTF("\n");
      return;
    }
  } else {
    PRINTF("RPL: Neighbor already in neighbor cache\n");
  }

  buffer_length = uip_len - uip_l3_icmp_hdr_len;

  /* Process the DIO base option. */
  i = 0;
  buffer = UIP_ICMP_PAYLOAD;

  dio.instance_id = buffer[i++];
  dio.version = buffer[i++];
  dio.rank = get16(buffer, i);
  i += 2;

  PRINTF("RPL: Incoming DIO (id, ver, rank) = (%u,%u,%u)\n",
         (unsigned)dio.instance_id,
         (unsigned)dio.version, 
         (unsigned)dio.rank);

  dio.grounded = buffer[i] & RPL_DIO_GROUNDED;
  dio.mop = (buffer[i]& RPL_DIO_MOP_MASK) >> RPL_DIO_MOP_SHIFT;
  dio.preference = buffer[i++] & RPL_DIO_PREFERENCE_MASK;

  dio.dtsn = buffer[i++];
  /* two reserved bytes */
  i += 2;

  memcpy(&dio.dag_id, buffer + i, sizeof(dio.dag_id));
  i += sizeof(dio.dag_id);

  PRINTF("RPL: Incoming DIO (dag_id, pref) = (");
  PRINT6ADDR(&dio.dag_id);
  PRINTF(", %u)\n", dio.preference);

  /* Check if there are any DIO suboptions. */
  for(; i < buffer_length; i += len) {
    subopt_type = buffer[i];
    if(subopt_type == RPL_OPTION_PAD1) {
      len = 1;
    } else {
      /* Suboption with a two-byte header + payload */
      len = 2 + buffer[i + 1];
    }

    if(len + i > buffer_length) {
      PRINTF("RPL: Invalid DIO packet\n");
      RPL_STAT(rpl_stats.malformed_msgs++);
      return;
    }

    PRINTF("RPL: DIO option %u, length: %u\n", subopt_type, len - 2);

    switch(subopt_type) {
    case RPL_OPTION_DAG_METRIC_CONTAINER:
      if(len < 6) {
        PRINTF("RPL: Invalid DAG MC, len = %d\n", len);
	RPL_STAT(rpl_stats.malformed_msgs++);
        return;
      }
      dio.mc.type = buffer[i + 2];
      dio.mc.flags = buffer[i + 3] << 1;
      dio.mc.flags |= buffer[i + 4] >> 7;
      dio.mc.aggr = (buffer[i + 4] >> 4) & 0x3;
      dio.mc.prec = buffer[i + 4] & 0xf;
      dio.mc.length = buffer[i + 5];

      if(dio.mc.type == RPL_DAG_MC_NONE) {
        /* No metric container: do nothing */
      } else if(dio.mc.type == RPL_DAG_MC_ETX) {
        dio.mc.obj.etx = get16(buffer, i + 6);

        PRINTF("RPL: DAG MC: type %u, flags %u, aggr %u, prec %u, length %u, ETX %u\n",
	       (unsigned)dio.mc.type,  
	       (unsigned)dio.mc.flags, 
	       (unsigned)dio.mc.aggr, 
	       (unsigned)dio.mc.prec, 
	       (unsigned)dio.mc.length, 
	       (unsigned)dio.mc.obj.etx);
      } else if(dio.mc.type == RPL_DAG_MC_ENERGY) {
        dio.mc.obj.energy.flags = buffer[i + 6];
        dio.mc.obj.energy.energy_est = buffer[i + 7];
      } else {
       PRINTF("RPL: Unhandled DAG MC type: %u\n", (unsigned)dio.mc.type);
       return;
      }
      break;
    case RPL_OPTION_ROUTE_INFO:
      if(len < 9) {
        PRINTF("RPL: Invalid destination prefix option, len = %d\n", len);
	RPL_STAT(rpl_stats.malformed_msgs++);
        return;
      }

      /* The flags field includes the preference value. */
      dio.destination_prefix.length = buffer[i + 2];
      dio.destination_prefix.flags = buffer[i + 3];
      dio.destination_prefix.lifetime = get32(buffer, i + 4);

      if(((dio.destination_prefix.length + 7) / 8) + 8 <= len &&
         dio.destination_prefix.length <= 128) {
        PRINTF("RPL: Copying destination prefix\n");
        memcpy(&dio.destination_prefix.prefix, &buffer[i + 8],
               (dio.destination_prefix.length + 7) / 8);
      } else {
        PRINTF("RPL: Invalid route info option, len = %d\n", len);
	RPL_STAT(rpl_stats.malformed_msgs++);
	return;
      }

      break;
    case RPL_OPTION_DAG_CONF:
      if(len != 16) {
        PRINTF("RPL: Invalid DAG configuration option, len = %d\n", len);
	RPL_STAT(rpl_stats.malformed_msgs++);
        return;
      }

      /* Path control field not yet implemented - at i + 2 */
      dio.dag_intdoubl = buffer[i + 3];
      dio.dag_intmin = buffer[i + 4];
      dio.dag_redund = buffer[i + 5];
      dio.dag_max_rankinc = get16(buffer, i + 6);
      dio.dag_min_hoprankinc = get16(buffer, i + 8);
      dio.ocp = get16(buffer, i + 10);
      /* buffer + 12 is reserved */
      dio.default_lifetime = buffer[i + 13];
      dio.lifetime_unit = get16(buffer, i + 14);
      PRINTF("RPL: DAG conf:dbl=%d, min=%d red=%d maxinc=%d mininc=%d ocp=%d d_l=%u l_u=%u\n",
             dio.dag_intdoubl, dio.dag_intmin, dio.dag_redund,
             dio.dag_max_rankinc, dio.dag_min_hoprankinc, dio.ocp,
             dio.default_lifetime, dio.lifetime_unit);
      break;
    case RPL_OPTION_PREFIX_INFO:
      if(len != 32) {
        PRINTF("RPL: Invalid DAG prefix info, len != 32\n");
	RPL_STAT(rpl_stats.malformed_msgs++);
        return;
      }
      dio.prefix_info.length = buffer[i + 2];
      dio.prefix_info.flags = buffer[i + 3];
      /* valid lifetime is ingnored for now - at i + 4 */
      /* preferred lifetime stored in lifetime */
      dio.prefix_info.lifetime = get32(buffer, i + 8);
      /* 32-bit reserved at i + 12 */
      PRINTF("RPL: Copying prefix information\n");
      memcpy(&dio.prefix_info.prefix, &buffer[i + 16], 16);
      break;
    default:
      PRINTF("RPL: Unsupported suboption type in DIO: %u\n",
	(unsigned)subopt_type);
    }
  }

#ifdef RPL_DEBUG_DIO_INPUT
  RPL_DEBUG_DIO_INPUT(&from, &dio);
#endif

  rpl_process_dio(&from, &dio);

  uip_len = 0;
}
/*---------------------------------------------------------------------------*/
void
dio_output(rpl_instance_t *instance, uip_ipaddr_t *uc_addr)
{
  unsigned char *buffer;
  int pos;
  rpl_dag_t *dag = instance->current_dag;
#if !RPL_LEAF_ONLY
  uip_ipaddr_t addr;
#endif /* !RPL_LEAF_ONLY */

#if RPL_LEAF_ONLY
  /* In leaf mode, we only send DIO messages as unicasts in response to 
     unicast DIS messages. */
  if(uc_addr == NULL) {
    PRINTF("RPL: LEAF ONLY have multicast addr: skip dio_output\n");
    return;
  }
#endif /* RPL_LEAF_ONLY */

  /* DAG Information Object */
  pos = 0;

  buffer = UIP_ICMP_PAYLOAD;
  buffer[pos++] = instance->instance_id;
  buffer[pos++] = dag->version;

#if RPL_LEAF_ONLY
  PRINTF("RPL: LEAF ONLY DIO rank set to INFINITE_RANK\n");
  set16(buffer, pos, INFINITE_RANK);
#else /* RPL_LEAF_ONLY */
  set16(buffer, pos, dag->rank);
#endif /* RPL_LEAF_ONLY */
  pos += 2;

  buffer[pos] = 0;
  if(dag->grounded) {
    buffer[pos] |= RPL_DIO_GROUNDED;
  }

  buffer[pos] |= instance->mop << RPL_DIO_MOP_SHIFT;
  buffer[pos] |= dag->preference & RPL_DIO_PREFERENCE_MASK;
  pos++;

  buffer[pos++] = instance->dtsn_out;

  /* always request new DAO to refresh route */
  RPL_LOLLIPOP_INCREMENT(instance->dtsn_out);

  /* reserved 2 bytes */
  buffer[pos++] = 0; /* flags */
  buffer[pos++] = 0; /* reserved */

  memcpy(buffer + pos, &dag->dag_id, sizeof(dag->dag_id));
  pos += 16;

#if !RPL_LEAF_ONLY
  if(instance->mc.type != RPL_DAG_MC_NONE) {
    instance->of->update_metric_container(instance);

    buffer[pos++] = RPL_OPTION_DAG_METRIC_CONTAINER;
    buffer[pos++] = 6;
    buffer[pos++] = instance->mc.type;
    buffer[pos++] = instance->mc.flags >> 1;
    buffer[pos] = (instance->mc.flags & 1) << 7;
    buffer[pos++] |= (instance->mc.aggr << 4) | instance->mc.prec;
    if(instance->mc.type == RPL_DAG_MC_ETX) {
      buffer[pos++] = 2;
      set16(buffer, pos, instance->mc.obj.etx);
      pos += 2;
    } else if(instance->mc.type == RPL_DAG_MC_ENERGY) {
      buffer[pos++] = 2;
      buffer[pos++] = instance->mc.obj.energy.flags;
      buffer[pos++] = instance->mc.obj.energy.energy_est;
    } else {
      PRINTF("RPL: Unable to send DIO because of unhandled DAG MC type %u\n",
	(unsigned)instance->mc.type);
      return;
    }
  }
#endif /* !RPL_LEAF_ONLY */

  /* Always add a DAG configuration option. */
  buffer[pos++] = RPL_OPTION_DAG_CONF;
  buffer[pos++] = 14;
  buffer[pos++] = 0; /* No Auth, PCS = 0 */
  buffer[pos++] = instance->dio_intdoubl;
  buffer[pos++] = instance->dio_intmin;
  buffer[pos++] = instance->dio_redundancy;
  set16(buffer, pos, instance->max_rankinc);
  pos += 2;
  set16(buffer, pos, instance->min_hoprankinc);
  pos += 2;
  /* OCP is in the DAG_CONF option */
  set16(buffer, pos, instance->of->ocp);
  pos += 2;
  buffer[pos++] = 0; /* reserved */
  buffer[pos++] = instance->default_lifetime;
  set16(buffer, pos, instance->lifetime_unit);
  pos += 2;

  /* Check if we have a prefix to send also. */
  if(dag->prefix_info.length > 0) {
    buffer[pos++] = RPL_OPTION_PREFIX_INFO;
    buffer[pos++] = 30; /* always 30 bytes + 2 long */
    buffer[pos++] = dag->prefix_info.length;
    buffer[pos++] = dag->prefix_info.flags;
    set32(buffer, pos, dag->prefix_info.lifetime);
    pos += 4;
    set32(buffer, pos, dag->prefix_info.lifetime);
    pos += 4;
    memset(&buffer[pos], 0, 4);
    pos += 4;
    memcpy(&buffer[pos], &dag->prefix_info.prefix, 16);
    pos += 16;
    PRINTF("RPL: Sending prefix info in DIO for ");
    PRINT6ADDR(&dag->prefix_info.prefix);
    PRINTF("\n");
  } else {
    PRINTF("RPL: No prefix to announce (len %d)\n",
           dag->prefix_info.length);
  }

#if RPL_LEAF_ONLY
#if (DEBUG) & DEBUG_PRINT
  if(uc_addr == NULL) {
    PRINTF("RPL: LEAF ONLY sending unicast-DIO from multicast-DIO\n");
  }
#endif /* DEBUG_PRINT */
  PRINTF("RPL: Sending unicast-DIO with rank %u to ",
      (unsigned)dag->rank);
  PRINT6ADDR(uc_addr);
  PRINTF("\n");
  uip_icmp6_send(uc_addr, ICMP6_RPL, RPL_CODE_DIO, pos);
#else /* RPL_LEAF_ONLY */
  /* Unicast requests get unicast replies! */
  if(uc_addr == NULL) {
    PRINTF("RPL: Sending a multicast-DIO with rank %u\n",
        (unsigned)instance->current_dag->rank);
    uip_create_linklocal_rplnodes_mcast(&addr);
    uip_icmp6_send(&addr, ICMP6_RPL, RPL_CODE_DIO, pos);
  } else {
    PRINTF("RPL: Sending unicast-DIO with rank %u to ",
        (unsigned)instance->current_dag->rank);
    PRINT6ADDR(uc_addr);
    PRINTF("\n");
    uip_icmp6_send(uc_addr, ICMP6_RPL, RPL_CODE_DIO, pos);
  }
#endif /* RPL_LEAF_ONLY */
}
/*---------------------------------------------------------------------------*/
static void
dao_input(void)
{
  uip_ipaddr_t dao_sender_addr;
  rpl_dag_t *dag;
  rpl_instance_t *instance;
  unsigned char *buffer;
  uint16_t sequence;
  uint8_t instance_id;
  uint8_t lifetime;
  uint8_t prefixlen;
  uint8_t flags;
  uint8_t subopt_type;
  /*
  uint8_t pathcontrol;
  uint8_t pathsequence;
  */
  uip_ipaddr_t prefix;
  uip_ds6_route_t *rep;
  uint8_t buffer_length;
  int pos;
  int len;
  int i;
  int learned_from;
  rpl_parent_t *parent;
  uip_ds6_nbr_t *nbr;

  prefixlen = 0;
  parent = NULL;

  uip_ipaddr_copy(&dao_sender_addr, &UIP_IP_BUF->srcipaddr);

  /* Destination Advertisement Object */
  PRINTF("RPL: Received a DAO from ");
  PRINT6ADDR(&dao_sender_addr);
  PRINTF("\n");

  buffer = UIP_ICMP_PAYLOAD;
  buffer_length = uip_len - uip_l3_icmp_hdr_len;

  pos = 0;
  instance_id = buffer[pos++];

  instance = rpl_get_instance(instance_id);
  if(instance == NULL) {
    PRINTF("RPL: Ignoring a DAO for an unknown RPL instance(%u)\n",
           instance_id);
    return;
  }

  lifetime = instance->default_lifetime;

  flags = buffer[pos++];
  /* reserved */
  pos++;
  sequence = buffer[pos++];

  dag = instance->current_dag;
  /* Is the DAG ID present? */
  if(flags & RPL_DAO_D_FLAG) {
    if(memcmp(&dag->dag_id, &buffer[pos], sizeof(dag->dag_id))) {
      PRINTF("RPL: Ignoring a DAO for a DAG different from ours\n");
      return;
    }
    pos += 16;
  }

  learned_from = uip_is_addr_mcast(&dao_sender_addr) ?
                 RPL_ROUTE_FROM_MULTICAST_DAO : RPL_ROUTE_FROM_UNICAST_DAO;

  PRINTF("RPL: DAO from %s\n",
         learned_from == RPL_ROUTE_FROM_UNICAST_DAO? "unicast": "multicast");
  if(learned_from == RPL_ROUTE_FROM_UNICAST_DAO) {
    /* Check whether this is a DAO forwarding loop. */
    parent = rpl_find_parent(dag, &dao_sender_addr);
    /* check if this is a new DAO registration with an "illegal" rank */
    /* if we already route to this node it is likely */
    if(parent != NULL &&
       DAG_RANK(parent->rank, instance) < DAG_RANK(dag->rank, instance)) {
      PRINTF("RPL: Loop detected when receiving a unicast DAO from a node with a lower rank! (%u < %u)\n",
          DAG_RANK(parent->rank, instance), DAG_RANK(dag->rank, instance));
      parent->rank = INFINITE_RANK;
      parent->flags |= RPL_PARENT_FLAG_UPDATED;
      return;
    }

    /* If we get the DAO from our parent, we also have a loop. */
    if(parent != NULL && parent == dag->preferred_parent) {
      PRINTF("RPL: Loop detected when receiving a unicast DAO from our parent\n");
      parent->rank = INFINITE_RANK;
      parent->flags |= RPL_PARENT_FLAG_UPDATED;
      return;
    }
  }

  /* Check if there are any RPL options present. */
  for(i = pos; i < buffer_length; i += len) {
    subopt_type = buffer[i];
    if(subopt_type == RPL_OPTION_PAD1) {
      len = 1;
    } else {
      /* The option consists of a two-byte header and a payload. */
      len = 2 + buffer[i + 1];
    }

    switch(subopt_type) {
    case RPL_OPTION_TARGET:
      /* Handle the target option. */
      prefixlen = buffer[i + 3];
      memset(&prefix, 0, sizeof(prefix));
      memcpy(&prefix, buffer + i + 4, (prefixlen + 7) / CHAR_BIT);
      break;
    case RPL_OPTION_TRANSIT:
      /* The path sequence and control are ignored. */
      /*      pathcontrol = buffer[i + 3];
              pathsequence = buffer[i + 4];*/
      lifetime = buffer[i + 5];
      /* The parent address is also ignored. */
      break;
    }
  }

  PRINTF("RPL: DAO lifetime: %u, prefix length: %u prefix: ",
          (unsigned)lifetime, (unsigned)prefixlen);
  PRINT6ADDR(&prefix);
  PRINTF("\n");

#if RPL_CONF_MULTICAST
  if(uip_is_addr_mcast_global(&prefix)) {
    mcast_group = uip_mcast6_route_add(&prefix);
    if(mcast_group) {
      mcast_group->dag = dag;
      mcast_group->lifetime = RPL_LIFETIME(instance, lifetime);
    }
    goto fwd_dao;
  }
#endif

  rep = uip_ds6_route_lookup(&prefix);

  if(lifetime == RPL_ZERO_LIFETIME) {
    PRINTF("RPL: No-Path DAO received\n");
    /* No-Path DAO received; invoke the route purging routine. */
    if(rep != NULL &&
       rep->state.nopath_received == 0 &&
       rep->length == prefixlen &&
       uip_ds6_route_nexthop(rep) != NULL &&
       uip_ipaddr_cmp(uip_ds6_route_nexthop(rep), &dao_sender_addr)) {
      PRINTF("RPL: Setting expiration timer for prefix ");
      PRINT6ADDR(&prefix);
      PRINTF("\n");
      rep->state.nopath_received = 1;
      rep->state.lifetime = DAO_EXPIRATION_TIMEOUT;

      /* We forward the incoming no-path DAO to our parent, if we have
         one. */
      if(dag->preferred_parent != NULL &&
         rpl_get_parent_ipaddr(dag->preferred_parent) != NULL) {
        PRINTF("RPL: Forwarding no-path DAO to parent ");
        PRINT6ADDR(rpl_get_parent_ipaddr(dag->preferred_parent));
        PRINTF("\n");
        uip_icmp6_send(rpl_get_parent_ipaddr(dag->preferred_parent),
                       ICMP6_RPL, RPL_CODE_DAO, buffer_length);
      }
      if(flags & RPL_DAO_K_FLAG) {
        dao_ack_output(instance, &dao_sender_addr, sequence);
      }
    }
    return;
  }

  PRINTF("RPL: adding DAO route\n");

  if((nbr = uip_ds6_nbr_lookup(&dao_sender_addr)) == NULL) {
    if((nbr = uip_ds6_nbr_add(&dao_sender_addr,
                              (uip_lladdr_t *)packetbuf_addr(PACKETBUF_ADDR_SENDER),
                              0, NBR_REACHABLE)) != NULL) {
      /* set reachable timer */
      //stimer_set(&nbr->reachable, UIP_ND6_REACHABLE_TIME / 1000);
      uip_ds6_if.reachable_time = uip_ds6_compute_reachable_time();
      stimer_set(&(nbr->reachable), uip_ds6_if.reachable_time / 1000);
      PRINTF("RPL: Neighbor added to neighbor cache ");
      PRINT6ADDR(&dao_sender_addr);
      PRINTF(", ");
      PRINTLLADDR((uip_lladdr_t *)packetbuf_addr(PACKETBUF_ADDR_SENDER));
      PRINTF("\n");
    } else {
      PRINTF("RPL: Out of Memory, dropping DAO from ");
      PRINT6ADDR(&dao_sender_addr);
      PRINTF(", ");
      PRINTLLADDR((uip_lladdr_t *)packetbuf_addr(PACKETBUF_ADDR_SENDER));
      PRINTF("\n");
      return;
    }
  } else {
    PRINTF("RPL: Neighbor already in neighbor cache\n");
  }
#if RPL_WHITE_LIST && !RPL_LEAF_ONLY
  uip_ds6_nbr_t *ds6_nbr = uip_ds6_nbr_lookup(&dao_sender_addr);
  const uip_lladdr_t *lladdr = uip_ds6_nbr_get_ll(ds6_nbr);
  int position = mac_in_white_list(lladdr);
  if (0 == memcmp(&prefix.u8[8], &dao_sender_addr.u8[0], 8)
          && 0 == white_list_button
          && (-1 == position || !mac_is_nbr(position)))
  {
      //根节点和路由节点,DAO target是发送者,而且按钮没按下,且不在白名单或者在白名单中但不是邻居,抛弃
      PRINTF("dao imme direct, button not set, ");
      uip_len = 0;
      return;
  }
#endif

#if RPL_WHITE_LIST && RPL_ROLE_ROUTER
  if (-1 == mac_in_white_list(lladdr)) {
    //路由节点,且不在白名单中,上传DAO到上一级,暂时保存数据,连接跟踪
    memcpy(&g_prefix, &prefix, sizeof(uip_ipaddr_t));
    memcpy(&g_dao_sender_addr, &dao_sender_addr, sizeof(uip_ipaddr_t));
    g_prefixlen = prefixlen;
    g_sequence = sequence;
    g_instance_id = instance_id;
    g_lifetime = lifetime;
    g_nbr = nbr;
    goto fwd_dao;
  }
  else {
    /* 在白名单中,直接回复dao ack */
    goto dao_ack;
  }
#endif
#if RPL_WHITE_LIST && CETIC_6LBR_DODAG_ROOT
  /* 根节点,已经在白名单或者加入白名单失败,直接return */
  if (0 == memcmp(&prefix.u8[8], &dao_sender_addr.u8[8], sizeof(uip_lladdr_t))) {
      /* 邻居 */
      if (-1 == mac_in_white_list(lladdr) 
            && -1 == addto_white_list(lladdr, lladdr, 1, 0, 0, 0))
      {
        uip_len = 0;
        return;
      }
  }
  else {
      /* 非邻居 */
      uip_lladdr_t prefix_lladdr = {{0}};
      memcpy(&prefix_lladdr, &prefix.u8[8], sizeof(uip_lladdr_t));
      prefix_lladdr.addr[0] ^= 0x02;
      if (-1 == mac_in_white_list(&prefix_lladdr) 
            && -1 == addto_white_list(&prefix_lladdr, lladdr, 0, 0, 0, 0))
      {
        uip_len = 0;
        return;
      }
  }
  nbr_table_lock(ds6_neighbors, nbr);
#endif
  /* 根节点,加入白名单成功,加入路由 */
  rpl_lock_parent(parent);

  /* prefix前缀是aaaa:: , dao_sender_addr前缀是fe80:: */
  rep = rpl_add_route(dag, &prefix, prefixlen, &dao_sender_addr);
  if(rep == NULL) {
    RPL_STAT(rpl_stats.mem_overflows++);
    PRINTF("RPL: Could not add a route after receiving a DAO\n");
    uip_len = 0;
    return;
  }

  rep->state.lifetime = RPL_LIFETIME(instance, lifetime);
  rep->state.learned_from = learned_from;
  rep->state.nopath_received = 0;

  goto dao_ack;

#if RPL_CONF_MULTICAST || RPL_WHITE_LIST
fwd_dao:
#endif

  if(learned_from == RPL_ROUTE_FROM_UNICAST_DAO) {
    if(dag->preferred_parent != NULL &&
       rpl_get_parent_ipaddr(dag->preferred_parent) != NULL) {
      PRINTF("RPL: Forwarding DAO to parent ");
      PRINT6ADDR(rpl_get_parent_ipaddr(dag->preferred_parent));
      PRINTF("\n");
      uip_icmp6_send(rpl_get_parent_ipaddr(dag->preferred_parent),
                     ICMP6_RPL, RPL_CODE_DAO, buffer_length);
    }
#if !RPL_WHITE_LIST
    if(flags & RPL_DAO_K_FLAG) {
      dao_ack_output(instance, &dao_sender_addr, sequence);
    }
#endif
  }
  uip_len = 0;
  return;

#if RPL_WHITE_LIST
/* 不会即转发给上级又发送dao ack,2选1 */
dao_ack:
#endif
  if(flags & RPL_DAO_K_FLAG) {
    dao_ack_output(instance, &dao_sender_addr, sequence);
  }
  uip_len = 0;
  return;
}
/*---------------------------------------------------------------------------*/
void
dao_output(rpl_parent_t *parent, uint8_t lifetime)
{
  /* Destination Advertisement Object */
  uip_ipaddr_t prefix;

  if(get_global_addr(&prefix) == 0) {
    PRINTF("RPL: No global address set for this node - suppressing DAO\n");
    return;
  }

  /* Sending a DAO with own prefix as target */
  dao_output_target(parent, &prefix, lifetime);
}
/*---------------------------------------------------------------------------*/
void
dao_output_target(rpl_parent_t *parent, uip_ipaddr_t *prefix, uint8_t lifetime)
{
  rpl_dag_t *dag;
  rpl_instance_t *instance;
  unsigned char *buffer;
  uint8_t prefixlen;
  int pos;

  /* Destination Advertisement Object */

  /* If we are in feather mode, we should not send any DAOs */
  if(rpl_get_mode() == RPL_MODE_FEATHER) {
    return;
  }

  if(parent == NULL) {
    PRINTF("RPL dao_output_target error parent NULL\n");
    return;
  }

  dag = parent->dag;
  if(dag == NULL) {
    PRINTF("RPL dao_output_target error dag NULL\n");
    return;
  }

  instance = dag->instance;

  if(instance == NULL) {
    PRINTF("RPL dao_output_target error instance NULL\n");
    return;
  }
  if(prefix == NULL) {
    PRINTF("RPL dao_output_target error prefix NULL\n");
    return;
  }
#ifdef RPL_DEBUG_DAO_OUTPUT
  RPL_DEBUG_DAO_OUTPUT(parent);
#endif

  buffer = UIP_ICMP_PAYLOAD;

  RPL_LOLLIPOP_INCREMENT(dao_sequence);
  pos = 0;

  buffer[pos++] = instance->instance_id;
  buffer[pos] = 0;
#if RPL_DAO_SPECIFY_DAG
  buffer[pos] |= RPL_DAO_D_FLAG;
#endif /* RPL_DAO_SPECIFY_DAG */
#if RPL_CONF_DAO_ACK
  buffer[pos] |= RPL_DAO_K_FLAG;
#endif /* RPL_CONF_DAO_ACK */
  ++pos;
  buffer[pos++] = 0; /* reserved */
  buffer[pos++] = dao_sequence;
#if RPL_DAO_SPECIFY_DAG
  memcpy(buffer + pos, &dag->dag_id, sizeof(dag->dag_id));
  pos+=sizeof(dag->dag_id);
#endif /* RPL_DAO_SPECIFY_DAG */

  /* create target subopt */
  prefixlen = sizeof(*prefix) * CHAR_BIT;
  buffer[pos++] = RPL_OPTION_TARGET;
  buffer[pos++] = 2 + ((prefixlen + 7) / CHAR_BIT);
  buffer[pos++] = 0; /* reserved */
  buffer[pos++] = prefixlen;
  memcpy(buffer + pos, prefix, (prefixlen + 7) / CHAR_BIT);
  pos += ((prefixlen + 7) / CHAR_BIT);

  /* Create a transit information sub-option. */
  buffer[pos++] = RPL_OPTION_TRANSIT;
  buffer[pos++] = 4;
  buffer[pos++] = 0; /* flags - ignored */
  buffer[pos++] = 0; /* path control - ignored */
  buffer[pos++] = 0; /* path seq - ignored */
  buffer[pos++] = lifetime;

  PRINTF("RPL: Sending DAO with prefix ");
  PRINT6ADDR(prefix);
  PRINTF(" to ");
  PRINT6ADDR(rpl_get_parent_ipaddr(parent));
  PRINTF("\n");

  if(rpl_get_parent_ipaddr(parent) != NULL) {
    uip_icmp6_send(rpl_get_parent_ipaddr(parent), ICMP6_RPL, RPL_CODE_DAO, pos);
  }
}
/*---------------------------------------------------------------------------*/
static void
dao_ack_input(void)
{
#if DEBUG || RPL_WHITE_LIST
  unsigned char *buffer;
  uint8_t buffer_length;
  uint8_t instance_id;
  uint8_t sequence;
  uint8_t status;
  rpl_instance_t *instance;
  uip_ds6_route_t *rep;
  rpl_dag_t *dag;
  int learned_from;

  buffer = UIP_ICMP_PAYLOAD;
  buffer_length = uip_len - uip_l3_icmp_hdr_len;

  instance_id = buffer[0];
  sequence = buffer[2];
  status = buffer[3];

  PRINTF("RPL: Received a DAO ACK with sequence number %d and status %d from ",
    sequence, status);
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF("\n");
  PRINTF("dao_sequence:%d, g_sequence:%d\n", dao_sequence, g_sequence);

  if (sequence == dao_sequence && sequence != 0)
  {
    //自己主动发送dao返回的ack
    int i,j;
    dao_sequence = 0;
    for(i = 0; i < RPL_MAX_INSTANCES; ++i) {
      if(instance_table[i].used == 1 && instance_table[i].dao_ack == 0) {
        instance_table[i].used = 1;
        instance_table[i].dao_ack = 1;

        for(j = 0; j < RPL_MAX_DAG_PER_INSTANCE; ++j) {
          if(instance_table[i].dag_table[j].used == 1 && instance_table[i].dag_table[j].dao_ack == 0) {
              instance_table[i].dag_table[j].used = 1;
              instance_table[i].dag_table[j].dao_ack = 1;
          }
        }

      }
    }
  }
#if !RPL_LEAF_ONLY
  else if (sequence == g_sequence && sequence != 0)
  {
    //转发的dao返回的ack
    uip_ds6_nbr_t *ds6_nbr = uip_ds6_nbr_lookup(&g_dao_sender_addr);
    const uip_lladdr_t *lladdr = uip_ds6_nbr_get_ll(ds6_nbr);
    g_sequence = 0;
    PRINTF("forward dao ack \n");
    //前缀不一样, prefix前缀aaaa:: , dao_sender_addr前缀fe80:: , 只比较mac部分
    if (0 == memcmp(&g_prefix.u8[8], &g_dao_sender_addr.u8[8], 8)) {
        //邻居
        PRINTF("forward dao ack , nexthop is nbr %p\n", &lladdr);
        if (-1 == mac_in_white_list(lladdr) 
              && -1 == addto_white_list(lladdr, lladdr, 1, 0, 0, 0))
        {
          PRINTF("add to white list fail\n");
          uip_len = 0;
          return;
        }
    }
    else {
        //非邻居
        PRINTF("forward dao ack , nexthop is not nbr %p\n", &lladdr);
        uip_lladdr_t prefix_lladdr = {{0}};
        memcpy(&prefix_lladdr, &g_prefix.u8[8], sizeof(uip_lladdr_t));
        g_prefix.u8[8] ^= 0x02;
        if (-1 == mac_in_white_list(lladdr) 
              && -1 == addto_white_list(&prefix_lladdr, lladdr, 0, 0, 0, 0))
        {
          PRINTF("add to white list fail\n");
          uip_len = 0;
          return;
        }
    }
    instance = rpl_get_instance(g_instance_id);
    dag = instance->current_dag;
    rep = rpl_add_route(dag, &g_prefix, g_prefixlen, &g_dao_sender_addr);
    if(rep == NULL) {
      RPL_STAT(rpl_stats.mem_overflows++);
      PRINTF("RPL: Could not add a route after receiving a DAO\n");
      uip_len = 0;
      return;
    }

    nbr_table_lock(ds6_neighbors, g_nbr);
    learned_from = uip_is_addr_mcast(&g_dao_sender_addr) ?
                 RPL_ROUTE_FROM_MULTICAST_DAO : RPL_ROUTE_FROM_UNICAST_DAO;

    rep->state.lifetime = RPL_LIFETIME(instance, g_lifetime);
    rep->state.learned_from = learned_from;
    rep->state.nopath_received = 0;

    PRINTF("RPL: Forwarding DAO ACK to nexthop\n");
    //转发给下一级
    //if(learned_from == RPL_ROUTE_FROM_UNICAST_DAO) {
      if(dag->preferred_parent != NULL &&
         rpl_get_parent_ipaddr(dag->preferred_parent) != NULL) {
        PRINTF("RPL: Forwarding DAO ACK to ");
        PRINT6ADDR(&g_dao_sender_addr);
        PRINTF("\n");
        uip_icmp6_send(&g_dao_sender_addr,
                       ICMP6_RPL, RPL_CODE_DAO_ACK, buffer_length);
      }
    //}
    uip_len = 0;
  }
#endif

#endif /* DEBUG */
  uip_len = 0;
}
/*---------------------------------------------------------------------------*/
void
dao_ack_output(rpl_instance_t *instance, uip_ipaddr_t *dest, uint8_t sequence)
{
  unsigned char *buffer;

#if RPL_WHITE_LIST && !RPL_LEAF_ONLY
  uip_ds6_nbr_t *ds6_nbr = uip_ds6_nbr_lookup(dest);
  const uip_lladdr_t *lladdr = uip_ds6_nbr_get_ll(ds6_nbr);
  if (-1 == mac_in_white_list(lladdr))
  {
      //不在白名单,不回复dao ack
      return;
  }
#endif

  PRINTF("RPL: Sending a DAO ACK with sequence number %d to ", sequence);
  PRINT6ADDR(dest);
  PRINTF("\n");

  buffer = UIP_ICMP_PAYLOAD;

  buffer[0] = instance->instance_id;
  buffer[1] = 0;
  buffer[2] = sequence;
  buffer[3] = 0;

  uip_icmp6_send(dest, ICMP6_RPL, RPL_CODE_DAO_ACK, 4);
}
/*---------------------------------------------------------------------------*/
void
rpl_icmp6_register_handlers()
{
  uip_icmp6_register_input_handler(&dis_handler);
  uip_icmp6_register_input_handler(&dio_handler);
  uip_icmp6_register_input_handler(&dao_handler);
  uip_icmp6_register_input_handler(&dao_ack_handler);
}
/*---------------------------------------------------------------------------*/
#endif /* UIP_CONF_IPV6 */
