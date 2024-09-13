#include "esp8266.h"
#include "usart.h"
#include "string.h" 
#include "oled.h"
#include <stdio.h>

uint8_t dtbuf[200];   								//打印缓存器	
extern unsigned char servernotok;
/////////////////////////////////////////////////////////////////////////////////////////////////////////// 
//ESP8266发送命令后,检测接收到的应答
//str:期待的应答结果
//返回值:0,没有得到期待的应答结果
//    其他,期待应答结果的位置(str的位置)
uint8_t* ESP8266_check_cmd(uint8_t *str)
{
	char *strx=0;
	if(USART_RX_STA == REC_OK)		//接收到一次数据了
	{ 
		strx=strstr((const char*)USART_RX_BUF,(const char*)str);
		memset(USART_RX_BUF,0,USART_REC_LEN);
	} 
	return (uint8_t*)strx;
}


//向ESP8266发送命令
//cmd:发送的命令字符串(不需要添加回车了),当cmd<0XFF的时候,发送数字(比如发送0X1A),大于的时候发送字符串.
//ack:期待的应答结果,如果为空,则表示不需要等待应答
//waittime:等待时间(单位:10ms)
//返回值:0,发送成功(得到了期待的应答结果)
//       1,发送失败
uint8_t ESP8266_send_cmd(uint8_t *cmd,uint8_t *ack,uint16_t waittime)
{
	uint8_t res=0; 
	//清空之前收到的数据
	memset(USART_RX_BUF,0,USART_REC_LEN);
	USART_RX_STA=0;
	
	printf("%s\r\n",cmd);
	USART2_printf("AT-->%s\r\n",cmd);  //调试打印接口，不需要串口打印时可取消
	if(ack&&waittime)		//需要等待应答
	{
		while(--waittime)
		{
			HAL_Delay(10);
			if(USART_RX_STA == REC_OK)//接收到期待的应答结果
			{
				USART2_printf("Recevie-->%s\r\n",(uint8_t *)USART_RX_BUF);	//发送到串口
				if(ESP8266_check_cmd(ack))break;//得到有效数据 
				USART_RX_STA=0;
			} 
		}
		if(waittime==0)res=1; 
	}
	USART_RX_STA=0;
	return res;
} 

//设置wifi和单片机链接和设置WiFi模块连接到路由器
uint8_t ESP8266_work_test(uint8_t *SSID,uint8_t *Password)
{
 
	OLED_ShowString(0,2,"               ");
	OLED_ShowString(0,2,"WIFI CONNECT ..");
	//发送AT命令使得STM32连接到 WiFi模块
	if(ESP8266_send_cmd((uint8_t *)"ATE0",(uint8_t *)"OK",200))
	{
		if(ESP8266_send_cmd((uint8_t *)"ATE0",(uint8_t *)"OK",200)) return WIFI_COMMUNTION_ERR;	//通信不上
	}		
	
	OLED_ShowString(0,2,"               ");
	OLED_ShowString(0,2,"WIFI SETMODE ..");
	//设置WiFi模块为AP+STA模式
	ESP8266_send_cmd((uint8_t *)"AT+CWMODE=3",(uint8_t *)"OK",200);	//设置WIFI模式
	
	OLED_ShowString(0,2,"               ");
	OLED_ShowString(0,2,"WIFI SETSSID ..");
	
	//设置WiFi模块连接到路由器
	memset(dtbuf,0,200);
	OLED_ShowString(0,4,"               ");
	OLED_ShowString(0,4,SSID);
	OLED_ShowString(0,6,"               ");
	OLED_ShowString(0,6,Password);
	sprintf((char *)dtbuf,"AT+CWJAP=\"%s\",\"%s\"",SSID,Password);
	if(ESP8266_send_cmd((uint8_t *)dtbuf,(uint8_t *)"WIFI GOT IP",1000))
	{
		return WIFI_CONN_FAIL;	//等待附着到网络
	}	
	return WIFI_OK;
}

uint8_t WIFI_Dect(uint8_t *SSID,uint8_t *Password)
{
	uint8_t res;
	HAL_Delay(500);
	res=ESP8266_work_test(SSID,Password);		
	switch(res)
	{
		case WIFI_OK:
			OLED_ShowString(0,2,"               ");
			OLED_ShowString(0,2,"WIFI SETSSID OK");
			break;
		case WIFI_COMMUNTION_ERR:
			OLED_ShowString(0,2,"               ");
			OLED_ShowString(0,2,"WIFI CONNECT NO");
			break;
		case WIFI_CONN_FAIL:
			OLED_ShowString(0,2,"               ");
			OLED_ShowString(0,2,"WIFI Network NO");
			break;		
		default:
			break;
	}
	return res;
}

//连接到服务器
uint8_t ESP8266_CONNECT_SERVER(uint8_t *ServerIP,uint8_t *Port)
{	  
		memset(dtbuf,0,200);
		OLED_ShowString(0,2,"               ");
		OLED_ShowString(0,2,"CONNE SERVER ..");
		OLED_ShowString(0,4,"               ");
		OLED_ShowString(0,4,ServerIP);
		OLED_ShowString(0,6,"               ");
		OLED_ShowString(0,6,Port);
		sprintf((char *)dtbuf,"AT+CIPSTART=\"TCP\",\"%s\",%s",ServerIP,Port);
		HAL_Delay(5000); //这里时间要长一点 不然就会变成busy .. ，。刚链接到wifi不能直接发送数据 
	  if(ESP8266_send_cmd((uint8_t *)dtbuf,(uint8_t *)"CONNECT",3000))	return 5;		
		//设置多模式
		if(ESP8266_send_cmd((uint8_t *)"AT+CIPMODE=1",(uint8_t *)"OK",100))	 return 1;
		//进入透传模式
		if(ESP8266_send_cmd((uint8_t *)"AT+CIPSEND",(uint8_t *)">",100))	 return 4;
	
		printf("***CONNECT SERVER SUCCEED***\r\n");
		USART_RX_STA=0;	
		servernotok=0;
	  return 0;                                                            
}
