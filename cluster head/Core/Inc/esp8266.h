#ifndef __ESP8266_H__
#define __ESP8266_H__	 
#include "main.h"
#include "gpio.h"
#include "usart.h"

#define WIFI_OK 0
#define WIFI_COMMUNTION_ERR 0xff
#define SIM_CPIN_ERR 0xfe
#define WIFI_CONN_FAIL 0xfd
#define SIM_MAKE_CALL_ERR 0Xfc
#define SIM_ATA_ERR       0xfb

#define SIM_CMGF_ERR 0xfa
#define SIM_CSCS_ERR 0xf9
#define SIM_CSCA_ERR 0xf8
#define SIM_CSMP_ERR 0Xf7
#define SIM_CMGS_ERR       0xf6
#define SIM_CMGS_SEND_FAIL       0xf5

#define SIM_CNMI_ERR 0xf4

uint8_t* ESP8266_check_cmd(uint8_t *str);
uint8_t ESP8266_send_cmd(uint8_t *cmd,uint8_t *ack,uint16_t waittime);
uint8_t WIFI_Dect(uint8_t *SSID,uint8_t *Password);
uint8_t ESP8266_CONNECT_SERVER(uint8_t *ServerIP,uint8_t *Port);


#endif

