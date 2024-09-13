/**
  ******************************************************************************
  * @file    usart.h
  * @brief   This file contains all the function prototypes for
  *          the usart.c file
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2022 CSTX.
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under BSD 3-Clause license,
  * the "License"; You may not use this file except in compliance with the
  * License. You may obtain a copy of the License at:
  *                        opensource.org/licenses/BSD-3-Clause
  *
  ******************************************************************************
  */
/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __USART_H__
#define __USART_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* USER CODE BEGIN Includes */
#include <stdarg.h>
#define USART_REC_LEN 256
#define REC_OK		1	   //接收完成标志
#define REC_WAIT	0	   //接收未完成标志
/* USER CODE END Includes */

extern UART_HandleTypeDef huart1;
extern UART_HandleTypeDef huart2;

/* USER CODE BEGIN Private defines */
extern uint8_t 	rxConut;         			 			  //数据长度	
extern uint8_t 	regConut;         			 			  //数据长度	
extern uint8_t  USART_RX_BUF[USART_REC_LEN]; 	//接收缓冲,最大USART_REC_LEN个字节
extern uint8_t  USART2_RX_BUF[USART_REC_LEN];
extern uint16_t USART_RX_STA;         			  //接收状态标记	
extern uint16_t USART2_RX_STA;
/* USER CODE END Private defines */

void MX_USART1_UART_Init(void);
void MX_USART2_UART_Init(void);

/* USER CODE BEGIN Prototypes */
void USER_UartHandler(UART_HandleTypeDef* huart);
void USART_Interupt_Enable(void);

void USART2_printf(char *fmt,...);  //usart2发送函数
void CS_Reg_Send_Data(unsigned char *buf,unsigned char len);
void cstx_reg_Receive_Data(unsigned char *buf,unsigned char *len);

/* USER CODE END Prototypes */

#ifdef __cplusplus
}
#endif

#endif /* __USART_H__ */

/************************ (C) COPYRIGHT CSTX *****END OF FILE****/
