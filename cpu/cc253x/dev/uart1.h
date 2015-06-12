#ifndef UART_1_H
#define UART_1_H

#include "contiki-conf.h"

#include "cc253x.h"
#include "8051def.h"
#include "uart.h"

/*---------------------------------------------------------------------------*/
/* UART1 Enable - Disable */
#ifdef UART1_CONF_ENABLE
#define UART1_ENABLE UART1_CONF_ENABLE
#else
#define UART1_ENABLE 0
#endif
/*---------------------------------------------------------------------------*/
/* UART1 Function Declarations */
#if UART1_ENABLE
void uart1_init();
void uart1_writeb(uint8_t byte);

void uart1_set_input(int (* input)(unsigned char c));
#if UART1_CONF_WITH_INPUT
#ifdef IAR_FOR_2530
  #pragma vector=URX1_VECTOR
  __near_func __interrupt void uart1_rx_isr(void);
#else
void uart1_rx_isr(void) __interrupt(URX1_VECTOR);
#endif
/* Macro to turn on / off UART RX Interrupt */
#define UART1_RX_INT(v) do { URX1IE = v; } while(0)
#define UART1_RX_EN()   do {   U1CSR |= UCSR_RE; } while(0)
#else
#define UART1_RX_INT(v)
#define UART1_RX_EN()
#endif /* UART1_CONF_WITH_INPUT */
#else
#define uart1_init(...)
#define uart1_writeb(...)
#define uart1_set_input(...)
#define UART1_RX_INT(v)
#define UART1_RX_EN()
#endif /* UART1_ENABLE */

#endif /* UART_1_H */
