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
 */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/*---------------------------------------------------------------------------*/
/* DIY ( iar can not read Makefile )                                         */
/*---------------------------------------------------------------------------*/
#undef UIP_CONF_IPV6
#define UIP_CONF_IPV6 1

#undef UIP_CONF_IPV6_RPL
#define UIP_CONF_IPV6_RPL 1

#undef RPL_CONF_LEAF_ONLY
#define RPL_CONF_LEAF_ONLY 1 //rpl叶子节点

#undef UIP_CONF_UDP
#define UIP_CONF_UDP 1

#undef WITH_COAP
#define WITH_COAP 13

#undef REST
#define REST coap_rest_implementation

#undef UIP_CONF_TCP
#define UIP_CONF_TCP 0

#undef UIP_CONF_ICMP6
#define UIP_CONF_ICMP6 0

#undef SICSLOWPAN_CONF_FRAG
#define SICSLOWPAN_CONF_FRAG 1

#undef UIP_CONF_IPV6_CHECKS
#define UIP_CONF_IPV6_CHECKS 1

//#define NULLRDC_CONF_ACK_WAIT_TIME (RTIMER_SECOND / 100)

#define KEEP_RADIO_ON 1 // contikimac 用到

//#define RFX2401C_ON 1 // PA

#define RPL_CONF_DAO_LATENCY 512 //dao回复时间范围,避免碰撞的机制

/*
 * csma重发时间1/NETSTACK_CONF_RDC_CHANNEL_CHECK_RATE,
 * rdc层contikimac也用到该值,在csma重发时间段内无限重发
 */
#define NETSTACK_CONF_RDC_CHANNEL_CHECK_RATE 8

#define UART1_PRIORITY_HIGH 1 //串口1优先级调到最高

#define DEBUG_FLAG 0 /* debug flag */
#define STARTUP_CONF_VERBOSE 0

#undef RF_CHANNEL
#define RF_CHANNEL 26

#undef WITH_DTLS_COAP
#define WITH_DTLS_COAP 0

#undef AUTOSTART_ENABLE
#define AUTOSTART_ENABLE 1

#undef UART0_CONF_ENABLE
#define UART0_CONF_ENABLE 0
#undef UART0_CONF_WITH_INPUT
#define UART0_CONF_WITH_INPUT 0
#undef UART1_CONF_ENABLE
#define UART1_CONF_ENABLE 1 // usb dongle 用串口1
#undef UART1_CONF_WITH_INPUT
#define UART1_CONF_WITH_INPUT 1

/*--------------------------------------------------------------------------*/

#undef QUEUEBUF_CONF_NUM
#define QUEUEBUF_CONF_NUM          4

#undef UIP_CONF_BUFFER_SIZE
#define UIP_CONF_BUFFER_SIZE    140

#undef UIP_CONF_ROUTER
#define UIP_CONF_ROUTER                 0

#undef UIP_CONF_IPV6_RPL
#define UIP_CONF_IPV6_RPL               0

#define CMD_CONF_OUTPUT slip_radio_cmd_output

#if RADIO_DEVICE_cc2420
#define CMD_CONF_HANDLERS slip_radio_cmd_handler,cmd_handler_cc2420
#elif CONTIKI_TARGET_SKY
/* add the cmd_handler_cc2420 + some sensors if TARGET_SKY */
#define CMD_CONF_HANDLERS slip_radio_cmd_handler,cmd_handler_cc2420
#define SLIP_RADIO_CONF_SENSORS slip_radio_sky_sensors
#elif CONTIKI_TARGET_Z1
/* add the cmd_handler_cc2420 */
#define CMD_CONF_HANDLERS slip_radio_cmd_handler,cmd_handler_cc2420
#elif CONTIKI_TARGET_CC2538DK
/* add the cmd_handler_cc2538 */
#define CMD_CONF_HANDLERS slip_radio_cmd_handler,cmd_handler_cc2538
#elif CONTIKI_TARGET_NOOLIBERRY
/* add the cmd_handler_rf230 if TARGET_NOOLIBERRY. Other RF230 platforms can be added */
#define CMD_CONF_HANDLERS slip_radio_cmd_handler,cmd_handler_rf230
#elif CONTIKI_TARGET_ECONOTAG
#define CMD_CONF_HANDLERS slip_radio_cmd_handler,cmd_handler_mc1322x
#else
#define CMD_CONF_HANDLERS slip_radio_cmd_handler
#endif


/* configuration for the slipradio/network driver */
#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC     nullmac_driver

/* NETSTACK_CONF_RDC is defined in Makefile */

#if CONTIKI_TARGET_ECONOTAG
#undef NULLRDC_CONF_802154_AUTOACK
#define NULLRDC_CONF_802154_AUTOACK_HW     1
#else
#undef NULLRDC_CONF_802154_AUTOACK
#define NULLRDC_CONF_802154_AUTOACK     1
#endif

#undef NETSTACK_CONF_NETWORK
#define NETSTACK_CONF_NETWORK slipnet_driver

#undef NETSTACK_CONF_FRAMER
#define NETSTACK_CONF_FRAMER no_framer

#undef CC2420_CONF_AUTOACK
#define CC2420_CONF_AUTOACK              1

#undef UART1_CONF_RX_WITH_DMA
#define UART1_CONF_RX_WITH_DMA           1

#undef UART1_CONF_TX_WITH_INTERRUPT
#define UART1_CONF_TX_WITH_INTERRUPT     1

#define UART1_CONF_TXBUFSIZE             512

#define UART1_CONF_RXBUFSIZE             512

#define IEEE802154_CONF_PANID            0xABCD

/* A slip radio does not need to go in deep sleep */
#define LPM_CONF_MAX_PM                  0

#define SLIP_CONF_TCPIP_INPUT()
#endif /* PROJECT_CONF_H_ */
