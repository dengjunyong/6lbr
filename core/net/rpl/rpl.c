/**
 * \addtogroup uip6
 * @{
 */
/*
 * Copyright (c) 2009, Swedish Institute of Computer Science.
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
 */
/**
 * \file
 *         ContikiRPL, an implementation of RPL: IPv6 Routing Protocol
 *         for Low-Power and Lossy Networks (IETF RFC 6550)
 *
 * \author Joakim Eriksson <joakime@sics.se>, Nicolas Tsiftes <nvt@sics.se>
 */

#include "net/ip/uip.h"
#include "net/ip/tcpip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-icmp6.h"
#include "net/rpl/rpl-private.h"
#include "net/ipv6/multicast/uip-mcast6.h"

#define DEBUG DEBUG_NONE
#include "net/ip/uip-debug.h"

#include <limits.h>
#include <string.h>

#if CETIC_6LBR_DODAG_ROOT
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#define WHITE_LIST_FILENAME "/etc/rpl_white_list"
#endif

#if RPL_WHITE_LIST && !RPL_LEAF_ONLY
//unsigned int white_list_count;
struct white_device white_list[UIP_CONF_MAX_ROUTES]; //和路由个数相同

extern uint8_t white_list_button;

//相等返回1
int mac_is_eq(const uip_lladdr_t *lladdr1, const uip_lladdr_t *lladdr2)
{
    int j = 0;
    int eq = 1;
    if (!lladdr1 || !lladdr2)
    {
        return 0;
    }
    for (j = 0; j < 8; j++)
    {
        if (lladdr1->addr[j] != lladdr2->addr[j])
        {
            eq = 0;
            break;
        }
    }
    return eq;
}

//为空返回1
int mac_is_null(const uip_lladdr_t *lladdr)
{
    if (!lladdr)
    {
        return 1;
    }
    uip_lladdr_t null_addr;
    memset(&null_addr, 0, 8);
    return mac_is_eq(lladdr, &null_addr);
}

//是邻居,返回1
int mac_is_nbr(int pos)
{
    if (pos >= UIP_CONF_MAX_ROUTES || pos < 0)
    {
        return 0;
    }
    if (0 == white_list[pos].used)
    {
        return 0;
    }
    return white_list[pos].isnbr;
}

//在白名单返回位置,否则返回-1
int mac_in_white_list(const uip_lladdr_t *lladdr)
{
  int i = 0;
  if (!lladdr)
  {
      return -1;
  }
  if (mac_is_null(lladdr))
  {
      return -1;
  }
  for (i = 0; i < UIP_CONF_MAX_ROUTES; i++)
  {
      if (!white_list[i].used)
      {
          break;
      }
      if (mac_is_eq(lladdr, &white_list[i].lladdr))
      {
          return i;
      }
  }
  return -1;
}

//增加成功返回位置,否则返回-1
int addto_white_list(const uip_lladdr_t *target, const uip_lladdr_t *nexthop,
           uint8_t isnbr, uint8_t role, uint8_t type, uint8_t ver)
{
    int i = 0;
    int ret = -1;
    int pos = 0;
    if (!target || !nexthop || mac_is_null(target)|| mac_is_null(nexthop))
    {
        return ret;
    }

    if (0 == isnbr) {
        //目标不是下一跳
        pos = mac_in_white_list(nexthop);
        if (pos == -1) {
            //下一跳不在白名单,异常
            return ret;
        }
    }

    if (-1 == mac_in_white_list(target)) {
        //不在白名单,添加
        for(; i < UIP_CONF_MAX_ROUTES; i++) {
            if (0 == white_list[i].used)
            {
                white_list[i].used = 1;
                white_list[i].role = role;
                white_list[i].type = type;
                white_list[i].ver = ver;
                white_list[i].isnbr = isnbr;
                white_list[i].nexthop_pos = pos;
                memcpy(&white_list[i].lladdr, target, sizeof(uip_lladdr_t));
                ret = i;
                write_white_list_conf();
                break;
            }
        }
    }
    return ret;
}

#if CETIC_6LBR_DODAG_ROOT
int write_white_list_conf()
{
    int fd = 0;
    fd = open(WHITE_LIST_FILENAME, O_RDWR | O_TRUNC);
    if (fd <= 0) {
        return -1;
    }
    int ret = write(fd, white_list, sizeof(white_list));
    close(fd);
    return ret;
}

void read_white_list_conf(uint8_t instance_id)
{
    int fd = 0;
    int i = 0;
    uip_ipaddr_t nexthop = {{0}};
    uip_ipaddr_t target = {{0}};
    uip_ds6_route_t *rep = NULL;
    uip_ds6_nbr_t *nbr = NULL;
    int learned_from = RPL_ROUTE_FROM_UNICAST_DAO;
    struct rpl_instance *instance = NULL;
    struct rpl_dag *dag = NULL;
    uint8_t lifetime = 0;

    if (0 != access(WHITE_LIST_FILENAME, F_OK)) {
        //配置文件不存在,创建
        memset(white_list, 0, sizeof(white_list));
        fd = open(WHITE_LIST_FILENAME, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IWOTH | S_IROTH);
        if (fd <= 0)
        {
            return;
        }
        write(fd, white_list, sizeof(white_list));
        close(fd);
        return;
    }

    fd = open(WHITE_LIST_FILENAME, O_RDWR);
    if (fd <= 0) {
        return;
    }
    int readret = read(fd, white_list, sizeof(white_list));
    close(fd);
    if (readret != sizeof(white_list)) {
        PRINTF("RPL read conf : whilt list length error\n");
        return;
    }

    instance = rpl_get_instance(instance_id);
    if(instance == NULL) {
      PRINTF("RPL: Ignoring a DAO for an unknown RPL instance(%u)\n",
             instance_id);
      return;
    }
    lifetime = instance->default_lifetime;
    dag = instance->current_dag;

    for(i = 0; i < UIP_CONF_MAX_ROUTES; i++) {
        if (0 == white_list[i].used) {
            continue;
        }
        if (1 == white_list[i].isnbr) {
            /* 增加邻居节点, nbr的ip前缀是fe80:: */
            uip_ip6addr(&target, 0xfe80, 0, 0, 0, 0, 0, 0, 0);
            uip_ds6_set_addr_iid(&target, &white_list[i].lladdr);
            if((nbr = uip_ds6_nbr_lookup(&target)) == NULL) {
              if((nbr = uip_ds6_nbr_add(&target, &white_list[i].lladdr,
                                        0, NBR_REACHABLE)) != NULL) {
                /* set reachable timer */
                stimer_set(&nbr->reachable, UIP_ND6_REACHABLE_TIME / 1000);
                /* lock,永久有效 */
                nbr_table_lock(ds6_neighbors, nbr);
                PRINTF("RPL read conf: Neighbor added to neighbor cache ");
                PRINT6ADDR(&target);
                PRINTF(", ");
                PRINTLLADDR(white_list[i].lladdr);
                PRINTF("\n");
              }
            } else {
              PRINTF("RPL read conf: Neighbor already in neighbor cache\n");
            }
        }
        //模拟DAO, target(prefix)前缀是aaaa::
        uip_ip6addr(&target, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
        uip_ds6_set_addr_iid(&target, &white_list[i].lladdr);
        if (1 == white_list[i].isnbr) {
            //邻居, 模拟DAO, nexthop(dao_sender_addr)前缀是fe80::
            uip_ip6addr(&nexthop, 0xfe80, 0, 0, 0, 0, 0, 0, 0);
            uip_ds6_set_addr_iid(&nexthop, &white_list[i].lladdr);
        }
        else {
            //非邻居
            if (white_list[i].nexthop_pos >= UIP_CONF_MAX_ROUTES)
            {
                //邻居编号不正确
                white_list[i].used = 0;
                continue;
            }
            if (0 == white_list[white_list[i].nexthop_pos].used) {
                //邻居编号对应的数据不可用
                white_list[i].used = 0;
                PRINTF("RPL read conf: data error!!!\n");
                continue;
            }
            uip_ip6addr(&nexthop, 0xfe80, 0, 0, 0, 0, 0, 0, 0);
            uip_ds6_set_addr_iid(&nexthop, &white_list[white_list[i].nexthop_pos].lladdr);
            if((nbr = uip_ds6_nbr_lookup(&nexthop)) == NULL) {
                if((nbr = uip_ds6_nbr_add(&nexthop, &white_list[white_list[i].nexthop_pos].lladdr,
                                          0, NBR_REACHABLE)) != NULL) {
                  /* set reachable timer */
                  stimer_set(&nbr->reachable, UIP_ND6_REACHABLE_TIME / 1000);
                  nbr_table_lock(ds6_neighbors, nbr);
                  PRINTF("RPL read conf: Neighbor added to neighbor cache ");
                  PRINT6ADDR(&target);
                  PRINTF(", ");
                  PRINTLLADDR(white_list[i].lladdr);
                  PRINTF("\n");
                }
            }
        }

        /* target前缀是aaaa::(dao_input()对应prefix) , nexthop前缀是fe80::(dao_input()对应dao_sender_addr)
         * 注意第三个参数,是位个数,而不是字节个数 */
        rep = rpl_add_route(dag, &target, sizeof(uip_ipaddr_t) * CHAR_BIT, &nexthop);
        if(rep == NULL) {
          RPL_STAT(rpl_stats.mem_overflows++);
          PRINTF("RPL: Could not add a route after receiving a DAO\n");
          uip_len = 0;
          return;
        }

        rep->state.lifetime = RPL_LIFETIME(instance, lifetime);
        rep->state.learned_from = learned_from;
        rep->state.nopath_received = 0;
    }
    return;
}

void *pthread_listen_white_list_button(void * arg)
{
    const char *fifo_name = "/tmp/rpl_white_list_fifo";
    int pipe_fd = -1;
    char buffer[10] = {0};
    int res = 0;

    pthread_detach(pthread_self());

    if(access(fifo_name, F_OK) == -1)
    {
        //管道文件不存在, 创建命名管道
        res = mkfifo(fifo_name, 777);
        if(res != 0)
        {
            perror("mkfifo");
            return NULL;
        }
    }

    while (1) {
        //open阻塞,直到另外一个进程O_WRONLY方式open才能退出阻塞
        pipe_fd = open(fifo_name, O_RDONLY);
        if(pipe_fd == -1) {
            perror("open");
            sleep(1);
            continue;
        }
        memset(buffer, 0, sizeof(buffer));
        res = read(pipe_fd, buffer, 5); //read默认阻塞
        if (res <= 0) {
            printf("read :%d\n", res);
            sleep(1);
            continue;
        }
        if (buffer[0] == '1') {
            white_list_button = 1;
            printf("white_list_button 1\n");
        }
        else if (buffer[0] == '0') {
            white_list_button = 0;
            printf("white_list_button 0\n");
        }
        close(pipe_fd);
        sleep(1);
    }
    return NULL;
}

void listen_white_list_button()
{
    pthread_t pthread_id;
    int ret = 0;
    ret = pthread_create(&pthread_id, NULL, pthread_listen_white_list_button, NULL);
    if(ret != 0){
        PRINTF("Create pthread listen button error!n");
    }
    return;
}
#else /* CETIC_6LBR_DODAG_ROOT */
int write_white_list_conf()
{
    return 0;
}

void read_white_list_conf(uint8_t instance_id)
{
    return;
}
void listen_white_list_button()
{
    return;
}
#endif /* CETIC_6LBR_DODAG_ROOT */

#endif /* RPL_WHITE_LIST && !RPL_LEAF_ONLY */


#if CETIC_6LBR_SMARTBRIDGE
extern void
send_purge_na(uip_ipaddr_t *prefix);
#endif

#if UIP_CONF_IPV6

#if RPL_CONF_STATS
rpl_stats_t rpl_stats;
#endif

static enum rpl_mode mode = RPL_MODE_MESH;
/*---------------------------------------------------------------------------*/
enum rpl_mode
rpl_get_mode(void)
{
  return mode;
}
/*---------------------------------------------------------------------------*/
enum rpl_mode
rpl_set_mode(enum rpl_mode m)
{
  enum rpl_mode oldmode = mode;

  /* We need to do different things depending on what mode we are
     switching to. */
  if(m == RPL_MODE_MESH) {

    /* If we switcht to mesh mode, we should send out a DAO message to
       inform our parent that we now are reachable. Before we do this,
       we must set the mode variable, since DAOs will not be send if
       we are in feather mode. */
    PRINTF("RPL: switching to mesh mode\n");
    mode = m;

    if(default_instance != NULL) {
      rpl_schedule_dao_immediately(default_instance);
    }
  } else if(m == RPL_MODE_FEATHER) {

    PRINTF("RPL: switching to feather mode\n");
    mode = m;
    if(default_instance != NULL) {
      rpl_cancel_dao(default_instance);
    }

  } else {
    mode = m;
  }

  return oldmode;
}
/*---------------------------------------------------------------------------*/
void
rpl_purge_routes(void)
{
  uip_ds6_route_t *r;
  uip_ipaddr_t prefix;
  rpl_dag_t *dag;
#if RPL_CONF_MULTICAST
  uip_mcast6_route_t *mcast_route;
#endif

  /* First pass, decrement lifetime */
  r = uip_ds6_route_head();

  while(r != NULL) {
    if(r->state.lifetime >= 1) {
      /*
       * If a route is at lifetime == 1, set it to 0, scheduling it for
       * immediate removal below. This achieves the same as the original code,
       * which would delete lifetime <= 1
       */
      r->state.lifetime--;
    }
    r = uip_ds6_route_next(r);
  }

  /* Second pass, remove dead routes */
  r = uip_ds6_route_head();

  while(r != NULL) {
    if(r->state.lifetime < 1) {
      /* Routes with lifetime == 1 have only just been decremented from 2 to 1,
       * thus we want to keep them. Hence < and not <= */
      uip_ipaddr_copy(&prefix, &r->ipaddr);
      uip_ds6_route_rm(r);
      r = uip_ds6_route_head();
      PRINTF("No more routes to ");
      PRINT6ADDR(&prefix);
      dag = default_instance->current_dag;
      /* Propagate this information with a No-Path DAO to preferred parent if we are not a RPL Root */
      if(dag->rank != ROOT_RANK(default_instance)) {
        PRINTF(" -> generate No-Path DAO\n");
        dao_output_target(dag->preferred_parent, &prefix, RPL_ZERO_LIFETIME);
        /* Don't schedule more than 1 No-Path DAO, let next iteration handle that */
        return;
      }
      PRINTF("\n");
    } else {
      r = uip_ds6_route_next(r);
    }
  }

#if RPL_CONF_MULTICAST
  mcast_route = uip_mcast6_route_list_head();

  while(mcast_route != NULL) {
    if(mcast_route->lifetime <= 1) {
      uip_mcast6_route_rm(mcast_route);
      mcast_route = uip_mcast6_route_list_head();
    } else {
      mcast_route->lifetime--;
      mcast_route = list_item_next(mcast_route);
    }
  }
#endif
}
/*---------------------------------------------------------------------------*/
void
rpl_remove_routes(rpl_dag_t *dag)
{
  uip_ds6_route_t *r;
#if RPL_CONF_MULTICAST
  uip_mcast6_route_t *mcast_route;
#endif

  r = uip_ds6_route_head();

  while(r != NULL) {
    if(r->state.dag == dag) {
      uip_ds6_route_rm(r);
      r = uip_ds6_route_head();
    } else {
      r = uip_ds6_route_next(r);
    }
  }

#if RPL_CONF_MULTICAST
  mcast_route = uip_mcast6_route_list_head();

  while(mcast_route != NULL) {
    if(mcast_route->dag == dag) {
      uip_mcast6_route_rm(mcast_route);
      mcast_route = uip_mcast6_route_list_head();
    } else {
      mcast_route = list_item_next(mcast_route);
    }
  }
#endif
}
/*---------------------------------------------------------------------------*/
void
rpl_remove_routes_by_nexthop(uip_ipaddr_t *nexthop, rpl_dag_t *dag)
{
  uip_ds6_route_t *r;

  r = uip_ds6_route_head();

  while(r != NULL) {
    if(uip_ipaddr_cmp(uip_ds6_route_nexthop(r), nexthop) &&
       r->state.dag == dag) {
      uip_ds6_route_rm(r);
      r = uip_ds6_route_head();
    } else {
      r = uip_ds6_route_next(r);
    }
  }
  ANNOTATE("#L %u 0\n", nexthop->u8[sizeof(uip_ipaddr_t) - 1]);
}
/*---------------------------------------------------------------------------*/
uip_ds6_route_t *
rpl_add_route(rpl_dag_t *dag, uip_ipaddr_t *prefix, int prefix_len,
              uip_ipaddr_t *next_hop)
{
  uip_ds6_route_t *rep;

  rep = uip_ds6_route_lookup(prefix);
  if(rep == NULL ||
     (uip_ds6_route_nexthop(rep) != NULL &&
      !uip_ipaddr_cmp(uip_ds6_route_nexthop(rep), next_hop))) {
    PRINTF("RPL: Add route for prefix ");
    PRINT6ADDR(prefix);
    PRINTF(" to ");
    PRINT6ADDR(next_hop);
    PRINTF("\n");
    if((rep = uip_ds6_route_add(prefix, prefix_len, next_hop)) == NULL) {
      PRINTF("RPL: No space for more route entries\n");
      return NULL;
    }
#if CETIC_6LBR_SMARTBRIDGE
    send_purge_na(prefix);
#endif
  }

  rep->state.dag = dag;
  rep->state.lifetime = RPL_LIFETIME(dag->instance, dag->instance->default_lifetime);
  rep->state.learned_from = RPL_ROUTE_FROM_INTERNAL;

  PRINTF("RPL: Added a route to ");
  PRINT6ADDR(prefix);
  PRINTF("/%d via ", prefix_len);
  PRINT6ADDR(next_hop);
  PRINTF("\n");

  return rep;
}
/*---------------------------------------------------------------------------*/
void
rpl_link_neighbor_callback(const linkaddr_t *addr, int status, int numtx)
{
  uip_ipaddr_t ipaddr;
  rpl_parent_t *parent;
  rpl_instance_t *instance;
  rpl_instance_t *end;

  uip_ip6addr(&ipaddr, 0xfe80, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, (uip_lladdr_t *)addr);

  for(instance = &instance_table[0], end = instance + RPL_MAX_INSTANCES; instance < end; ++instance) {
    if(instance->used == 1 ) {
      parent = rpl_find_parent_any_dag(instance, &ipaddr);
      if(parent != NULL) {
        /* Trigger DAG rank recalculation. */
        PRINTF("RPL: rpl_link_neighbor_callback triggering update\n");
        parent->flags |= RPL_PARENT_FLAG_UPDATED;
        if(instance->of->neighbor_link_callback != NULL) {
          instance->of->neighbor_link_callback(parent, status, numtx);
        }
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
void
rpl_ipv6_neighbor_callback(uip_ds6_nbr_t *nbr)
{
  rpl_parent_t *p;
  rpl_instance_t *instance;
  rpl_instance_t *end;

  PRINTF("RPL: Removing neighbor ");
  PRINT6ADDR(&nbr->ipaddr);
  PRINTF("\n");
  for(instance = &instance_table[0], end = instance + RPL_MAX_INSTANCES; instance < end; ++instance) {
    if(instance->used == 1 ) {
      p = rpl_find_parent_any_dag(instance, &nbr->ipaddr);
      if(p != NULL) {
        p->rank = INFINITE_RANK;
        /* Trigger DAG rank recalculation. */
        PRINTF("RPL: rpl_ipv6_neighbor_callback infinite rank\n");
        p->flags |= RPL_PARENT_FLAG_UPDATED;
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
void
rpl_purge_dags(void)
{
  rpl_instance_t *instance;
  rpl_instance_t *end;
  int i;

  for(instance = &instance_table[0], end = instance + RPL_MAX_INSTANCES;
      instance < end; ++instance) {
    if(instance->used) {
      for(i = 0; i < RPL_MAX_DAG_PER_INSTANCE; i++) {
        if(instance->dag_table[i].used) {
          if(instance->dag_table[i].lifetime == 0) {
            if(!instance->dag_table[i].joined) {
              rpl_free_dag(&instance->dag_table[i]);
            }
          } else {
            instance->dag_table[i].lifetime--;
          }
        }
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
void
rpl_init(void)
{
  uip_ipaddr_t rplmaddr;
  PRINTF("RPL started\n");
  default_instance = NULL;

  rpl_dag_init();
  rpl_reset_periodic_timer();
  rpl_icmp6_register_handlers();

  /* add rpl multicast address */
  uip_create_linklocal_rplnodes_mcast(&rplmaddr);
  uip_ds6_maddr_add(&rplmaddr);

#if RPL_CONF_STATS
  memset(&rpl_stats, 0, sizeof(rpl_stats));
#endif

  RPL_OF.reset(NULL);
#if RPL_WHITE_LIST && !RPL_LEAF_ONLY
  //监听按钮
  listen_white_list_button();
#endif
}
/*---------------------------------------------------------------------------*/
#endif /* UIP_CONF_IPV6 */
