/**
  ******************************************************************************
  * @file    usart.c
  * @brief   This file provides code for the configuration
  *          of the USART instances.
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

/* Includes ------------------------------------------------------------------*/
#include "usart.h"

/* USER CODE BEGIN 0 */
#include "stdio.h"
#include "string.h"

uint8_t rxConut = 0;										 //数据长度
uint8_t regConut = 0;
uint16_t USART_RX_STA=0;       					 //接收状态标记
uint16_t USART2_RX_STA=0;
uint8_t USART_RX_BUF[USART_REC_LEN];     //接收缓冲,最大USART_REC_LEN个字节.
uint8_t USART2_RX_BUF[USART_REC_LEN];

__align(8) char usart_txBuff[USART_REC_LEN];      //字节对齐缓冲区

#ifdef __GNUC__
  /* With GCC/RAISONANCE, small printf (option LD Linker->Libraries->Small printf
     set to 'Yes') calls __io_putchar() */
  #define PUTCHAR_PROTOTYPE int __io_putchar(int ch)
#else
  #define PUTCHAR_PROTOTYPE int fputc(int ch, FILE *f)
#endif /* __GNUC__ */
/**
  * @brief  Retargets the C library printf function to the USART.
  * @param  None
  * @retval None
  */
PUTCHAR_PROTOTYPE
{
  /* Place your implementation of fputc here */
  /* e.g. write a character to the EVAL_COM1 and Loop until the end of transmission */
  HAL_UART_Transmit(&huart1, (uint8_t *)&ch, 1, 0xFFFF);
 
  return ch;
}


//usart2的printf()
void USART2_printf(char *fmt,...)
{
  uint32_t i,length;
  va_list ap;
  va_start(ap,fmt);
  vsprintf(usart_txBuff,fmt,ap);
  va_end(ap);
  length=strlen((const char*)usart_txBuff);
  while((USART2->ISR&0x40)==0);
  for(i=0;i<length;i++)
  {
//      printf("%02x ", usart_txBuff[i]);
    USART2->TDR=usart_txBuff[i];
    while((USART2->ISR&0x40)==0);
  }
}
/* USER CODE END 0 */

UART_HandleTypeDef huart1;
UART_HandleTypeDef huart2;

/* USART1 init function */

void MX_USART1_UART_Init(void)
{

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart1.Init.ClockPrescaler = UART_PRESCALER_DIV1;
  huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetTxFifoThreshold(&huart1, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetRxFifoThreshold(&huart1, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_DisableFifoMode(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */

}
/* USART2 init function */

void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 9600;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  huart2.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart2.Init.ClockPrescaler = UART_PRESCALER_DIV1;
  huart2.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */

}

void HAL_UART_MspInit(UART_HandleTypeDef* uartHandle)
{

  GPIO_InitTypeDef GPIO_InitStruct = {0};
  if(uartHandle->Instance==USART1)
  {
  /* USER CODE BEGIN USART1_MspInit 0 */

  /* USER CODE END USART1_MspInit 0 */
    /* USART1 clock enable */
    __HAL_RCC_USART1_CLK_ENABLE();

    __HAL_RCC_GPIOB_CLK_ENABLE();
    /**USART1 GPIO Configuration
    PB7     ------> USART1_RX
    PB6     ------> USART1_TX
    */
    GPIO_InitStruct.Pin = GPIO_PIN_7|GPIO_PIN_6;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    GPIO_InitStruct.Alternate = GPIO_AF0_USART1;
    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

    /* USART1 interrupt Init */
    HAL_NVIC_SetPriority(USART1_IRQn, 0, 0);
    HAL_NVIC_EnableIRQ(USART1_IRQn);
  /* USER CODE BEGIN USART1_MspInit 1 */

  /* USER CODE END USART1_MspInit 1 */
  }
  else if(uartHandle->Instance==USART2)
  {
  /* USER CODE BEGIN USART2_MspInit 0 */

  /* USER CODE END USART2_MspInit 0 */
    /* USART2 clock enable */
    __HAL_RCC_USART2_CLK_ENABLE();

    __HAL_RCC_GPIOA_CLK_ENABLE();
    /**USART2 GPIO Configuration
    PA2     ------> USART2_TX
    PA3     ------> USART2_RX
    */
    GPIO_InitStruct.Pin = GPIO_PIN_2|GPIO_PIN_3;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    GPIO_InitStruct.Alternate = GPIO_AF1_USART2;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    /* USART2 interrupt Init */
    HAL_NVIC_SetPriority(USART2_IRQn, 0, 0);
    HAL_NVIC_EnableIRQ(USART2_IRQn);
  /* USER CODE BEGIN USART2_MspInit 1 */

  /* USER CODE END USART2_MspInit 1 */
  }
}

void HAL_UART_MspDeInit(UART_HandleTypeDef* uartHandle)
{

  if(uartHandle->Instance==USART1)
  {
  /* USER CODE BEGIN USART1_MspDeInit 0 */

  /* USER CODE END USART1_MspDeInit 0 */
    /* Peripheral clock disable */
    __HAL_RCC_USART1_CLK_DISABLE();

    /**USART1 GPIO Configuration
    PB7     ------> USART1_RX
    PB6     ------> USART1_TX
    */
    HAL_GPIO_DeInit(GPIOB, GPIO_PIN_7|GPIO_PIN_6);

    /* USART1 interrupt Deinit */
    HAL_NVIC_DisableIRQ(USART1_IRQn);
  /* USER CODE BEGIN USART1_MspDeInit 1 */

  /* USER CODE END USART1_MspDeInit 1 */
  }
  else if(uartHandle->Instance==USART2)
  {
  /* USER CODE BEGIN USART2_MspDeInit 0 */

  /* USER CODE END USART2_MspDeInit 0 */
    /* Peripheral clock disable */
    __HAL_RCC_USART2_CLK_DISABLE();

    /**USART2 GPIO Configuration
    PA2     ------> USART2_TX
    PA3     ------> USART2_RX
    */
    HAL_GPIO_DeInit(GPIOA, GPIO_PIN_2|GPIO_PIN_3);

    /* USART2 interrupt Deinit */
    HAL_NVIC_DisableIRQ(USART2_IRQn);
  /* USER CODE BEGIN USART2_MspDeInit 1 */

  /* USER CODE END USART2_MspDeInit 1 */
  }
}

/* USER CODE BEGIN 1 */
void USART_Interupt_Enable(void)
{

	__HAL_UART_ENABLE_IT(&huart1,UART_IT_IDLE);    //空闲中断使能
	__HAL_UART_ENABLE_IT(&huart1,UART_IT_RXNE); 	 //接收中断使能
	__HAL_UART_CLEAR_IDLEFLAG(&huart1);
	__HAL_UART_ENABLE_IT(&huart2,UART_IT_IDLE);    //空闲中断使能
	__HAL_UART_ENABLE_IT(&huart2,UART_IT_RXNE); 	 //接收中断使能
	__HAL_UART_CLEAR_IDLEFLAG(&huart2);
	
}

//void  USART1_IdleCallback(uint8_t*pData,uint16_t len)
//{
//	while(__HAL_UART_GET_FLAG(&huart1,UART_FLAG_TC)!=SET);
//	HAL_UART_Transmit(&huart2,pData,len,1000);
//}
//void  USART2_IdleCallback(uint8_t*pData,uint16_t len)
//{
//	while(__HAL_UART_GET_FLAG(&huart2,UART_FLAG_TC)!=SET);
//	HAL_UART_Transmit(&huart1,pData,len,1000);
//}

/*串口中断处理函数*/
void USER_UartHandler(UART_HandleTypeDef* huart)
{
	uint8_t res = 0;
	static uint8_t OnPow = 1,OnPow2 = 1;
	if(huart->Instance == USART1)
	{
		//接收中断
		if(__HAL_UART_GET_FLAG(&huart1,UART_FLAG_RXNE)!=RESET)
		{
			HAL_UART_Receive(&huart1,&res,1,1000);
			//将数据放入缓冲区
			if(rxConut<USART_REC_LEN)
			{
				USART_RX_BUF[rxConut]=res;
				rxConut++;
			}
			USART_RX_STA  = REC_WAIT ;
			__HAL_UART_CLEAR_FLAG(&huart1,UART_FLAG_RXNE);
		}
		//空闲中断
		if(__HAL_UART_GET_FLAG(&huart1,UART_FLAG_IDLE)!=RESET)
		{
			//一帧数据接收完成
			if(OnPow)
			{
				USART_RX_STA  = REC_WAIT ;
				OnPow = 0;
			}else {USART_RX_STA  = REC_OK;}
			//USART1_IdleCallback(USART_RX_BUF,rxConut);
			rxConut =0;
			__HAL_UART_CLEAR_IDLEFLAG(&huart1);
		}
	}else if(huart->Instance == USART2)
	{
		//接收中断
		if(__HAL_UART_GET_FLAG(&huart2,UART_FLAG_RXNE)!=RESET)
		{
			HAL_UART_Receive(&huart2,&res,1,1000);
			//将数据放入缓冲区
			if(rxConut<USART_REC_LEN)
			{
				USART2_RX_BUF[rxConut]=res;
				rxConut++;
				regConut++;
			}
			USART2_RX_STA  = REC_WAIT ;
			__HAL_UART_CLEAR_FLAG(&huart2,UART_FLAG_RXNE);
		}
		//空闲中断
		if(__HAL_UART_GET_FLAG(&huart2,UART_FLAG_IDLE)!=RESET)
		{
			//一帧数据接收完成
			if(OnPow2)
			{
				USART2_RX_STA  = REC_WAIT ;
				OnPow2 = 0;
			}else {USART2_RX_STA  = REC_OK;}
			//USART2_IdleCallback(USART2_RX_BUF,rx2Conut);
			rxConut =0;
			__HAL_UART_CLEAR_IDLEFLAG(&huart2);
		}
	}
}

//发送len个字节.
//buf:发送区首地址
//len:发送的字节数(为了和本代码的接收匹配,这里建议不要超过64个字节)
void CS_Reg_Send_Data(unsigned char *buf,unsigned char len)
{
	unsigned char t;
	 while((USART2->ISR&0x40)==0);
  for(t=0;t<len;t++)		//循环发送数据
	{		   
    USART2->TDR=buf[t];
    while((USART2->ISR&0x40)==0);
	}	 
	regConut=0;	  
	memset(USART2_RX_BUF,0,USART_REC_LEN);
}



//查询接收到的数据
//buf:接收缓存首地址
//len:读到的数据长度
void cstx_reg_Receive_Data(unsigned char *buf,unsigned char *len)
{
	unsigned char rxlen=regConut;
	unsigned char i=0;
	*len=0;				//默认为0

	if(USART2_RX_BUF[0]==0XC1)//接收到了数据,且接收完成了
	{
		for(i=0;i<rxlen;i++)
		{
			buf[i]=USART2_RX_BUF[i];	
		}		
		*len=regConut;	//记录本次数据长度
	}
//	regConut=0;		//清零
	memset(USART2_RX_BUF,0,USART_REC_LEN);
}

/* USER CODE END 1 */

/************************ (C) COPYRIGHT CSTX *****END OF FILE****/
