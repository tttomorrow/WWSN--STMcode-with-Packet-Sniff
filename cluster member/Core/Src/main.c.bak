/**
 * @file send/main.c
 * @author cl wang (wangcl929@hust.edu.cn)
 * @brief
 * @version 0.1
 * @date 2024-09-13
 *
 * @copyright Copyright (c) 2024
 *
 */
#include "main.h"
#include "usart.h"
#include "gpio.h"
#include "dht11.h"
#include <stdio.h>
#include "string.h"
#include "oled.h"
#include <stdlib.h>

#define SDATA "ToggleLED\r\n" // 定义字符串常量用于串口发送数据
#define ROUTE_REQUEST 0x01
#define ROUTE_REPLY 0x02
#define DATA_PACKET 0x03
#define ACK_PACKET 0x04
#define ROUTING_TABLE_SIZE_INITIAL 10
#define SNIFF_TABLE_SIZE_INITIAL 0
#define MacH 0xFF
#define MacL 0xFF      ///////////////////////////////////////////
#define channelID 0x09 // 信道ID

uint8_t nodeID = 2; // 节点ID///////////////////////////////////////////////

// 数据包结构体
typedef struct
{
    uint8_t destMacH; // 数据包第1字节
    uint8_t destMacL;
    uint8_t destchanID; // 源节点ID
    uint8_t sourceMacH; // 数据包第4字节
    uint8_t sourceMacL;
    uint8_t sourceID;    // 源节点ID
    uint8_t forwardID;   // 转发节点ID
    uint8_t forwardtoID; // 转发地址节点ID
    uint8_t destID;      // 目的节点ID
    uint8_t protocol;    // 协议类型
    uint8_t ID;          // 添加数据包唯一id，nodeID加数据包ID 11字节
    char data[40];       // 自定义数据
} DataPacket;

// 路由表
typedef struct
{
    uint8_t destID;    // 目的节点ID
    uint8_t nextHopID; // 下一跳节点ID
    uint8_t macHigh;   // 下一跳节点高MAC地址
    uint8_t macLow;    // 下一跳节点低MAC地址
} RoutingEntry;

// 监听表 12字节
// 监听表的格式（被监听id，监听者id，转发数据包个数，发送传感器数据次数，ack次数，路由查询次数，路由回复次数,最近一次监听到数据包时的RSSI强度）
typedef struct
{
    uint32_t lastSniffTime; // 最近更新时间
    uint8_t sourceID;
    uint8_t snifferID;
    uint8_t forwardCount;
    uint8_t sourceCount;
    uint8_t ackCount;
    uint8_t routeReqCount;
    uint8_t routeRepCount;
    uint8_t lastRSSI;
} SnifferTable;

void SystemClock_Config(void);
void sendRouteRequest(uint8_t destID);
void sendRouteReply(uint8_t destID, uint8_t sourceID);
void sendAddressResolution(uint8_t targetID);
void sendAckPacket(uint8_t destID, uint8_t macH, uint8_t macL);
void handleReceivedPacket(DataPacket *packet);
void processRouteRequest(DataPacket *packet);
void processRouteReply(DataPacket *packet);
void processDataPacket(DataPacket *packet);
void processAckPacket(DataPacket *packet);
int findSniffID(uint8_t forwardID);
void sniff(DataPacket *packet);

unsigned char key = 0; // 用于保存接收到的寄存器代码
unsigned char RSSIkey = 0;
unsigned char disOLED[24]; // 用于OLED显示的数组
uint8_t targetID = 1;      // 汇聚节点ID1
char nodeIDStr[8];         // 用于存储节点ID的字符串
RoutingEntry *routingTable = NULL;
int routingTableSize = ROUTING_TABLE_SIZE_INITIAL; // 路由表大小
int routingTableCount = 0;
SnifferTable *sniffTable = NULL;
int sniffTableSize = SNIFF_TABLE_SIZE_INITIAL; // 监听表大小
int sniffTableCount = 1;
unsigned char packetBUF[sizeof(DataPacket)];
uint32_t previousMillisA0 = 0; // 计时发送温度数据
uint32_t previousMillisA1 = 0; // 路由请求发送时间
uint8_t sendRoutRequest = 0;   // 路由请求标志
uint8_t getRoutReplay = 0;     // 路由回复标志位
uint8_t RSSI = 0;
uint8_t packetID = 1;         // 数据包计数
uint8_t sniffTableSendID = 0; // 已发送监听表计数

// 通过配置寄存器 设置lora模块信道与地址
// 初始mac地址为广播地址0x10 0x02，所有节点统一采用信道0x09；具体配置查询手册
unsigned char cscxReg[10] = {0xC0, 0x00, 0x07, 0x10, 0x02, 0x01, 0x61, 0x20, 0x09, 0xD0};
; // 发送查询数据
// 配置模块地址（0x1001）、网络地址（0x01,该地址不能变）、串口（9600 8N1）、空速（2.4K）、
// 启用发射前信道监听、启用顶点传输（串口前三个字节为地址高，地址低，信道，一同作为无线发射目标）
//    unsigned char cscxRegCha[4] = {0xC0, 0x05, 0x01, 0x09}; // 配置模块信道为0x09
unsigned char csrevReg[12] = {0xC1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // 接收寄存器数据

// 监听表的格式（被监听id，监听者id，转发数据包个数，发送传感器数据次数，ack次数，路由查询次数，路由回复次数）
// 添加监听数据
/**
 * @brief 处理监听到的数据包
 *
 * @param packet
 */
void sniff(DataPacket *packet)
{
    if (sniffTableCount >= sniffTableSize)
    {
        sniffTableSize += 1;
        sniffTable = (SnifferTable *)realloc(sniffTable, sniffTableSize * sizeof(SnifferTable));
    }

    int sniffIndex = findSniffID(packet->forwardID);
    //    printf("sniffIndex: %d, forwardID: %02x", sniffIndex, packet->forwardID);
    if (sniffIndex == -1)
    {
        sniffIndex = sniffTableCount - 1;
        sniffTable[sniffIndex].lastSniffTime = HAL_GetTick();
        sniffTable[sniffIndex].sourceID = packet->forwardID;
        sniffTable[sniffIndex].snifferID = nodeID;
        sniffTable[sniffIndex].forwardCount = 0;
        sniffTable[sniffIndex].sourceCount = 0;
        sniffTable[sniffIndex].ackCount = 0;
        sniffTable[sniffIndex].routeReqCount = 0;
        sniffTable[sniffIndex].routeRepCount = 0;
        sniffTableCount++;
    }
    sniffTable[sniffIndex].lastSniffTime = HAL_GetTick();
    sniffTable[sniffIndex].lastRSSI = RSSI;
    switch (packet->protocol)
    {
    case ROUTE_REQUEST:
        sniffTable[sniffIndex].routeReqCount++;
        break;
    case ROUTE_REPLY:
        sniffTable[sniffIndex].routeRepCount++;
        break;
    case DATA_PACKET:
        if (packet->sourceID == packet->forwardID)
        {
            sniffTable[sniffIndex].sourceCount++;
        }
        else
        {
            sniffTable[sniffIndex].forwardCount++;
        }
        break;
    case ACK_PACKET:
        sniffTable[sniffIndex].ackCount++;
        break;
    default:
        break;
    }
}

/**
 * @brief 查询被监听节点是否已存在于监听表中
 *
 * @param forwardID
 * @return int
 */
int findSniffID(uint8_t forwardID)
{
    for (int i = 0; i < sniffTableCount; i++)
    {
        // printf("sniffTablesourceID: %02X, forwardID: %02x", sniffTable[i].sourceID, forwardID);
        if (sniffTable[i].sourceID == forwardID)
        {
            return i;
        }
    }
    return -1; // 未找到
}

/**
 * @brief 配置lora模块
 *
 */
void configureModule()
{
    cscxReg[3] = MacH;
    cscxReg[4] = MacL;
    // 其他配置代码...
}

// 获取环境噪声RSSI
/**
 * @brief Get the Envir RSSI object
 *
 */
int getEnvirRSSI()
{
    uint8_t envirRssi;
    // 检查M1是否被成功置为0,M0是否被成功置为1,WOR模式
    if (HAL_GPIO_ReadPin(M0_GPIO_Port, M0_Pin) == 0 && HAL_GPIO_ReadPin(M1_GPIO_Port, M1_Pin) == 0)
    {
        printf("\r\n M1 = 0; M0 = 0 \r\n");

        unsigned char cscxRSSIreq2[6] = {0xC0, 0xC1, 0xC2, 0xC3, 0x00, 0x01};
        unsigned char cscxRSSI[4] = {0x00, 0x00, 0x00, 0x00};
        CS_Reg_Send_Data(cscxRSSIreq2, sizeof(cscxRSSIreq2)); // 发送 cscxRSSIreq2 到寄存器
        HAL_Delay(500);                                       // 延迟  毫秒
        cstx_reg_Receive_Data(cscxRSSI, &RSSIkey);         // 接收寄存器的数据
        printf("\r\n\r\nLORA REG CODE %d REG->", RSSIkey); // 打印 LORA 寄存器代码和寄存器信息
        for (int i = 0; i < 4; i++)                        // 逐字节打印接收到的寄存器数据
        {
            printf("%02X", cscxRSSI[i]);
            printf(" ");
        }
        printf("\n");
        envirRssi = cscxRSSI[3];
        printf("\r\ncurrentChannelNoise: -%ddBm\r\n", 256 - envirRssi);
        printf("\r\ncurrentChannelSNR: %ddB\r\n", RSSI - cscxRSSI[3]);
    }
    return envirRssi;
}

// 添加路由条目
/**
 * @brief 添加路由条目到路由表
 *
 * @param destID
 * @param nextHopID
 * @param macHigh
 * @param macLow
 */
void addRoutingEntry(uint8_t destID, uint8_t nextHopID, uint8_t macHigh, uint8_t macLow)
{
    if (routingTableCount >= routingTableSize)
    {
        routingTableSize *= 2;
        routingTable = (RoutingEntry *)realloc(routingTable, routingTableSize * sizeof(RoutingEntry));
    }
    routingTable[routingTableCount].destID = destID;
    routingTable[routingTableCount].nextHopID = nextHopID;
    routingTable[routingTableCount].macHigh = macHigh;
    routingTable[routingTableCount].macLow = macLow;
    routingTableCount++;
}

// 打印路由表
/**
 * @brief 打印路由表
 *
 */
void printRoutingTable()
{
    for (int i = 0; i < routingTableCount; i++)
    {
        printf("\r\nEntry %d: DestID = %02X, NextHopID = %02X, MAC = %02X%02X\n",
               i,
               routingTable[i].destID,
               routingTable[i].nextHopID,
               routingTable[i].macHigh,
               routingTable[i].macLow);
    }
}

/**
 * @brief 查询路由表中是否包含数据包destID的下一个转发ID，若有，则返回路由表条目
 *
 * @param destID
 * @return int
 */
int findRoute(uint8_t destID)
{
    printf("\r\nRoute table:");
    for (int i = 0; i < routingTableCount; i++)
    {
        printf("%02X=%02X, ", routingTable[i].destID, destID);
        if (routingTable[i].destID == destID)
        {
            printf("; Routeindex: i=%d\r\n", i);
            OLED_ShowString(0, 4, "find route to 1");
            return i;
        }
    }
    return -1; // 未找到路由
}

/**
 * @brief 发送路由查询数据包，查询数据包目的id为FF，查询的目的地址为destID（汇聚节点）
 *
 * @param destID
 */
void sendRouteRequest(uint8_t destID)
{
    DataPacket packet;
    packet.ID = packetID++;
    packet.destMacH = 0xFF;
    packet.destMacL = 0xFF;
    packet.destchanID = channelID;
    packet.sourceMacH = MacH;
    packet.sourceMacL = MacL;
    packet.sourceID = nodeID;
    packet.forwardID = nodeID;
    packet.forwardtoID = 0xFF;
    packet.destID = destID;
    packet.protocol = ROUTE_REQUEST;
    for (int i = 0; i < sizeof(packet.data); i++)
    {
        packet.data[i] = 0xFF;
    }
    memset(packetBUF, 0, sizeof(packet));
    memcpy(packetBUF, &packet, sizeof(DataPacket));
    USART2_printf("%s\r\n", packetBUF);
    printf("\r\nRoute Request sent to find node %d\r\n", destID);
}

// 路由回复
// 数据包目的id为destID， 只要告诉查询节点自己可以到即可，源id等于转发id，目的id等于转发到id
/**
 * @brief 路由回复  数据包目的id为destID，只要告诉查询节点自己可以到即可，源id等于转发id，目的id等于转发到id
 *
 * @param destID
 * @param forwardID
 */
void sendRouteReply(uint8_t destID, uint8_t forwardID)
{
    DataPacket packet;
    packet.ID = packetID++;
    packet.destMacH = 0xFF;
    packet.destMacL = 0xFF;
    packet.destchanID = channelID;
    packet.sourceMacH = MacH;
    packet.sourceMacL = MacL;
    packet.sourceID = nodeID;
    packet.forwardID = nodeID;
    packet.forwardtoID = destID;
    packet.destID = destID;
    packet.protocol = ROUTE_REPLY;
    for (int i = 0; i < sizeof(packet.data); i++)
    {
        packet.data[i] = 0xFF;
    }
    memset(packetBUF, 0, sizeof(packet));
    memcpy(packetBUF, &packet, sizeof(DataPacket));
    USART2_printf("%s\r\n", packetBUF);
    printf("\r\nRoute Reply sent to %d from node %d\r\n", destID, nodeID);
}

/**
 * @brief 发送ACK数据包 源id等于转发id，目的id等于转发到id
 *
 * @param destID
 * @param macH
 * @param macL
 */
void sendAckPacket(uint8_t destID, uint8_t macH, uint8_t macL)
{
    DataPacket packet;
    packet.ID = packetID++;
    packet.destMacH = macH;
    packet.destMacL = macL;
    packet.destchanID = channelID;
    packet.sourceID = nodeID;
    packet.sourceMacH = MacH;
    packet.sourceMacL = MacL;
    packet.forwardID = nodeID;
    packet.forwardtoID = destID;
    packet.destID = destID;
    packet.protocol = ACK_PACKET;
    for (int i = 0; i < sizeof(packet.data); i++)
    {
        packet.data[i] = 0xFF;
    }
    memset(packetBUF, 0, sizeof(packet));
    memcpy(packetBUF, &packet, sizeof(packet));
    USART2_printf("%s\r\n", packetBUF);
    printf("\r\nAcknowledgement sent to %d\r\n", destID);
}

/**
 * @brief 处理接收到的数据包
 *
 * @param packet
 */
void handleReceivedPacket(DataPacket *packet)
{
    switch (packet->protocol)
    {
    case ROUTE_REQUEST:
        processRouteRequest(packet);
        break;
    case ROUTE_REPLY:
        processRouteReply(packet);
        break;
    case DATA_PACKET:
        processDataPacket(packet);
        break;
    case ACK_PACKET:
        processAckPacket(packet);
        break;
    default:
        printf("Unknown protocol: %d\r\n", packet->protocol);
        break;
    }
}

/**
 * @brief 处理路由查询报文
 *
 * @param packet
 */
void processRouteRequest(DataPacket *packet)
{
    // 查询路由表，查找目标地址的路由
    int routeIndex = findRoute(packet->destID);
    // 处理路由请求逻辑
    // 如果发送过路由请求且该请求查询的路径终点与之前查询的一致，则不做任何操作

    // 查询路由表
    printf("\r\nReceived Route Request from %d\r\n", packet->sourceID);
    if (routeIndex != -1)
    {
        // 路由表中有地址
        sendRouteReply(packet->sourceID, routingTable[routeIndex].nextHopID);
    }
    else
    {
        // 路由表中没地址
        if (sendRoutRequest == 1)
        {
            // 如果之前发送过路由查询报文
            return;
        }
        printf("\r\nNo route found for destination node %d\r\n", packet->destID);
        sendRouteRequest(packet->destID);
        previousMillisA1 = HAL_GetTick();
        sendRoutRequest = 1;
    }
}

/**
 * @brief 处理路由回复报文
 *
 * @param packet
 */
void processRouteReply(DataPacket *packet)
{
    printf("\r\nReceived Route Reply from %02X%02X, \r\npacket sourceID:%02X, \r\nforwardID:%02X, \r\ndestID:%02X\r\n", packet->sourceMacH,
           packet->sourceMacL, packet->sourceID, packet->forwardID, packet->destID);
    // 处理路由回复逻辑
    int routeIndex = findRoute(packet->destID);
    // 路由表中没该信息或者有不同的路径则添加路由
    if (routeIndex == -1 || routingTable[routeIndex].nextHopID != packet->sourceID)
    {

        addRoutingEntry(targetID, packet->sourceID, packet->sourceMacH, packet->sourceMacL);
        getRoutReplay = 1;
        printf("\r\nAddRoutingEntry\r\n");
    }
}

/**
 * @brief 处理数据包报文
 *
 * @param packet
 */
void processDataPacket(DataPacket *packet)
{
    printf("\r\nReceived Data Packet from %d with node %d forward\r\n", packet->sourceID, packet->forwardID);
    // 处理数据包逻辑
    if (packet->destID == nodeID)
    {
        // 自己是数据包的终点，只有汇聚节点是终点
        memset(disOLED, 0, 32);
        sprintf((char *)disOLED, "T:%d.%dC H:%d.%dR", packet->data[0], packet->data[1], packet->data[2], packet->data[3]);
        printf("\r\nReceive Date :");
        OLED_ShowString(0, 6, disOLED);
        for (int i = 0; i < 16; i++)
        {
            printf("%4X", USART2_RX_BUF[i]);
        } // 通过电脑来接收

        // 将数据包发送到服务器（添加上汇聚节点的操作）
        // 发送ack数据包
        sendAckPacket(packet->forwardID, packet->sourceMacH, packet->sourceMacL);
        printf("\r\n");
        memset(USART2_RX_BUF, 0, USART_REC_LEN);
        USART2_RX_STA = 0;
        getEnvirRSSI();
    }
    else
    {
        // 自己不是数据包的终点
        // 发送ack数据包
        sendAckPacket(packet->forwardID, packet->sourceMacH, packet->sourceMacL);
        uint8_t envirRSSI = getEnvirRSSI();
        // 查询路由表，查找目标地址的路由
        int routeIndex = findRoute(targetID);
        printf("\r\nrouteIndex: %d\r\n", routeIndex);
        // 有到数据包终点的路由 （如果接收到发给自己的数据包，就意味着自己的路由表有到终点的路由，这是因为前一步进行了路由回复）
        if (routeIndex != -1)
        {
            packet->destMacH = 0xFF;
            packet->destMacL = 0xFF;
            packet->destchanID = 0x09;
            packet->sourceMacH = MacH;
            packet->sourceMacL = MacL;

            packet->forwardID = nodeID;
            packet->forwardtoID = routingTable[routeIndex].nextHopID;
            // 从数据包第29字节开始向后遍历，直到找到第一个为0的三字节 记录数据包路径、信号强度和环境噪声
            for (int i = 28; i >= 0; i = i+3)
            {
                if (packet->data[i] == 0)
                {
                    packet->data[i] = nodeID;
                    packet->data[i+1] = RSSI;
                    packet->data[i+2] = envirRSSI;
                    break;
                }
            }
            for (int i = 0; i < sizeof(packet->data); i++)
            {
                if (packet->data[i] == 0x00)
                {
                    packet->data[i] = 0xFF;
                }
            }
            memset(packetBUF, 0, sizeof(packet));
            printf("\r\nforward datapacket from node %d to node %d\r\n", packet->sourceID, packet->forwardtoID);
            memcpy(packetBUF, packet, sizeof(DataPacket));
            USART2_printf("%s\r\n", packetBUF);
        }
        // 如果没有到终点的路由（暂时没写，只有链接断了才能不可达终点；后续添加路由查询与路由失败报文）
    }
}

/**
 * @brief 处理ACK数据包
 *
 * @param packet
 */
void processAckPacket(DataPacket *packet)
{
    printf("\r\nReceived Acknowledgement from %d\r\n", packet->sourceID);
    packet->destMacH = packet->sourceMacH;
    packet->destMacL = packet->sourceMacL;
    packet->sourceMacH = MacH;
    packet->sourceMacL = MacL;

    // 处理确认包逻辑
}

/**
 * @brief 主函数
 *
 * @return int
 */
int main(void)
{
    int i;
    /* MCU Configuration--------------------------------------------------------*/

    HAL_Init(); // 初始化 HAL 库

    // 初始化路由表
    // 初始化路由表
    routingTableSize = 2; // 初始路由表大小
    routingTable = (RoutingEntry *)malloc(routingTableSize * sizeof(RoutingEntry));

    SystemClock_Config(); // 配置系统时钟

    MX_GPIO_Init();        // 初始化 GPIO 端口
    MX_USART1_UART_Init(); // 初始化 USART1 端口
    MX_USART2_UART_Init(); // 初始化 USART2 端口

    USART_Interupt_Enable(); // 使能串口接收中断和空闲中断

    printf("LORA Board LED OK\r\n"); // 打印 LORA 板的 LED 状态信息
    sprintf(nodeIDStr, "%d", nodeID);
    CS_OLED_Init();                                      // 初始化 OLED 显示屏
    OLED_Clear();                                        // 清除 OLED 显示屏内容
    OLED_ShowString(16, 0, "WWSN NODE");                 // 在 OLED 显示屏上显示字符串 "WWSN NODE"
    printf("\r\nWWSN Node %d\r\n", nodeID);              // 打印nodeID
    OLED_ShowString(100, 0, (unsigned char *)nodeIDStr); // 在 OLED 显示屏上显示节点ID
    cstxInitialize();                                    // 初始化 LED 并使其闪烁
    configureModule();

    // 通过配置寄存器 设置lora模块信道与地址
    //    configureModule();
    if (HAL_GPIO_ReadPin(M1_GPIO_Port, M1_Pin) == 1) // 检查 GPIO 引脚 M1 的电平状态，只有在高电平时才开始读取模块的寄存器
    {
        printf("\r\nM1 = 1 ; M0 = 0 Register mode \r\n");     // 打印 M1 和 M0 的状态信息，表示处于寄存器模式
        CS_Reg_Send_Data(cscxReg, sizeof(cscxReg));           // 发送 cscxReg 到寄存器
        HAL_Delay(300);                                       // 延迟 300 毫秒
        printf("\r\n\r\nLORA REG CODE %d UART2->", regConut); // 打印 LORA 寄存器代码和 UART2 信息

        for (i = 0; i < 12; i++) // 逐字节打印 USART2 接收缓冲区的数据
        {
            printf("%02X", USART2_RX_BUF[i]);
            printf(" ");
        }

        cstx_reg_Receive_Data(csrevReg, &key);         // 接收寄存器的数据
        printf("\r\n\r\nLORA REG CODE %d REG->", key); // 打印 LORA 寄存器代码和寄存器信息
        memset(disOLED, 0, 24);                        // 清空 disOLED 数组

        for (i = 0; i < 12; i++) // 逐字节打印接收到的寄存器数据
        {
            printf("%02X", csrevReg[i]);
            printf(" ");
        }

        OLED_ShowString(0, 2, "Addr:"); // 在 OLED 显示屏上显示 "Addr:"
        for (i = 3; i < 5; i++)         // 显示寄存器的地址信息
        {
            sprintf((char *)disOLED, "%02X", csrevReg[i]);
            //        printf("disOLED=%s,", disOLED);
            OLED_ShowString(i * 16 - 4, 2, disOLED);
        }

        OLED_ShowString(82, 2, "Ch:"); // 在 OLED 显示屏上显示 "Ch:"
        sprintf((char *)disOLED, "%02X", csrevReg[8]);
        //        printf("disOLED=%s\r\n", disOLED);
        OLED_ShowString(104, 2, disOLED);
    }
    else
    {
        printf("\r\nM1 = 0; M0 = 0 Transparent mode \r\n"); // 打印 M1 和 M0 的状态信息，表示处于透明模式
    }

    memset(USART2_RX_BUF, 0, USART_REC_LEN); // 清空接收缓冲区
    USART2_RX_STA = 0;
    /* 无限循环 */
    /* USER CODE BEGIN WHILE */
    // 循环读取传感器数据并发送
    HAL_GPIO_WritePin(M1_GPIO_Port, M1_Pin, GPIO_PIN_RESET); // 使能模块运行 M1 0
    if (HAL_GPIO_ReadPin(M1_GPIO_Port, M1_Pin) == 0)
    {
        printf("\r\nM1 = 0; M0 = 0 Transparent mode \r\n");
    }
    HAL_Init();

    uint32_t currentMillis; // 获取当前系统时间

    addRoutingEntry(nodeID, nodeID, MacH, MacL);
    DataPacket receivedPacket;
    DataPacket datapacket;
    while (1)
    {

        currentMillis = HAL_GetTick();
        if (currentMillis - previousMillisA0 >= 40000 || previousMillisA0 == 0) // 当前时间刻减去前次执行的时间刻
        {
            previousMillisA0 = currentMillis; // 更新执行时间刻

            //        OLED_ShowString(0, 4, "Send data ......"); // 在 OLED 显示屏上显示 "Send data ......"

            if (DHT11_READ_DATA() == 1) // 读取 DHT11 数据
            {

                printf("\r\nRead DHT11 Succeed \r\n");
                //        USART2_printf("A,%d.%d%%,%d.%d", Dht11data[0], Dht11data[1], Dht11data[2], Dht11data[3]); // 打印读取到的 DHT11 数据
                datapacket.data[0] = Dht11data[2];
                datapacket.data[1] = Dht11data[3];
                datapacket.data[2] = Dht11data[0];
                datapacket.data[3] = Dht11data[1];

                memset(disOLED, 0, 32); // 清空 disOLED 数组
                sprintf((char *)disOLED, "T:%d.%dC H:%d.%dR", datapacket.data[0], datapacket.data[1], datapacket.data[2], datapacket.data[3]);
                OLED_ShowString(0, 6, disOLED); // 在 OLED 显示屏上显示格式化后的 DHT11 数据

                // 查询路由表，查找目标地址的路由
                int routeIndex = findRoute(targetID);
                printf("\r\nRouteIndex: %d\r\n", routeIndex);
                if (routeIndex != -1)
                {
                    // 构建数据缓冲区并发送
                    // 发送数据包
                    datapacket.destMacH = routingTable[routeIndex].macHigh;
                    datapacket.destMacL = routingTable[routeIndex].macLow;
                    datapacket.destchanID = channelID; // 信道0
                    datapacket.sourceMacH = MacH;
                    datapacket.sourceMacL = MacL;
                    datapacket.sourceID = nodeID;
                    datapacket.forwardID = nodeID;
                    datapacket.forwardtoID = routingTable[routeIndex].nextHopID;
                    datapacket.destID = targetID;
                    datapacket.ID = packetID++;
                    datapacket.protocol = DATA_PACKET;

                    memcpy(&datapacket.data[4], &sniffTable[sniffTableSendID % sniffTableCount], sizeof(SnifferTable));
                    sniffTableSendID++;
                    if (sniffTableCount > 1)
                    {
                        memcpy(&datapacket.data[4 + sizeof(SnifferTable)], &sniffTable[sniffTableSendID % sniffTableCount], sizeof(SnifferTable));
                        sniffTableSendID++;
                    }
                    for (int i = 0; i < sizeof(datapacket.data); i++)
                    {
                        if (datapacket.data[i] == 0x00)
                        {
                            datapacket.data[i] = 0xFF;
                        }
                    }

                    //                printf("packet: %d, %d, %d, %x, %s\n",
                    //                                    (int)packet.sourceID,
                    //                                    (int)packet.forwardID,
                    //                                    (int)packet.destID,
                    //                                     packet.protocol,
                    //                                     packet.data);
                    printf("\r\nRoute found for destination node\r\n");

                    memcpy(packetBUF, &datapacket, sizeof(datapacket));
                    printf("Send packet to %02X\r\n", datapacket.forwardtoID);

                    USART2_printf("%s\r\n", packetBUF);
                }
                else
                {
                    printf("\r\nNo route found for destination node %d\r\n", targetID);
                    sendRouteRequest(targetID);
                    previousMillisA1 = HAL_GetTick();
                    sendRoutRequest = 1;
                    getRoutReplay = 0;
                }
            }
        }

        if (sendRoutRequest == 1 && getRoutReplay == 0)
        {
            currentMillis = HAL_GetTick(); // 获取当前系统时间
            if (currentMillis - previousMillisA1 > 20000 && getRoutReplay == 0)
            {
                sendRouteRequest(targetID);
                previousMillisA1 = HAL_GetTick();
            }
        }

        // 处理LORA 发送过来的数据
        if (USART2_RX_STA == REC_OK) // 检查是否接收到数据
        {
            //        printf("\r\nReceive data with protocol:%02X\r\n",  USART2_RX_BUF[5]);
            receivedPacket.sourceMacH = USART2_RX_BUF[0];
            receivedPacket.sourceMacL = USART2_RX_BUF[1];
            receivedPacket.sourceID = USART2_RX_BUF[2];
            receivedPacket.forwardID = USART2_RX_BUF[3];
            receivedPacket.forwardtoID = USART2_RX_BUF[4];
            receivedPacket.destID = USART2_RX_BUF[5];
            receivedPacket.protocol = USART2_RX_BUF[6];
            receivedPacket.ID = USART2_RX_BUF[7];
            memcpy(receivedPacket.data, &USART2_RX_BUF[8], sizeof(receivedPacket) - 6);

            for (int i = 0; i < sizeof(datapacket.data); i++)
            {
                if (receivedPacket.data[i] == 0xFF)
                {
                    receivedPacket.data[i] = 0x00;
                }
            }
            // 从数据包末尾开始向前遍历，直到找到第一个非零字节
            for (int i = 65 - 1; i >= 0; i--)
            {
                if (USART2_RX_BUF[i] != 0)
                {
                    RSSI = USART2_RX_BUF[i];
                    printf("\r\nreceivedPacketWithRSSI :-%ddBm\r\n", 256 - RSSI);
                    break;
                }
            }
            for (int i = 0; i < 65; i++)
            {
                printf("%02X ", USART2_RX_BUF[i]);
            }
            //        sscanf((char*)USART2_RX_BUF, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%s",
            //                                                &receivedPacket.sourceMacH,
            //                                                &receivedPacket.sourceMacL,
            //                                                &receivedPacket.sourceID,
            //                                                &receivedPacket.forwardID,
            //                                                &receivedPacket.destID,
            //                                                &receivedPacket.protocol,
            //                                                receivedPacket.data);
            if (receivedPacket.forwardtoID == nodeID || receivedPacket.destID == nodeID || receivedPacket.protocol == ROUTE_REQUEST)
            {
                printf("\r\nhandleReceivedPackethandleReceivedPacket\r\n");
                handleReceivedPacket(&receivedPacket);
                sniff(&receivedPacket);
            }
            else
            {
                printf("\r\nhandleSniffPackethandleSniffPacket\r\n");
                sniff(&receivedPacket);
            }

            memset(USART2_RX_BUF, 0, USART_REC_LEN); // 清空接收缓冲区
            USART2_RX_STA = 0;                       // 重置接收状态
        }

        // 电脑发送过来的数据(测试用)
        if (USART_RX_STA == REC_OK)
        {
            printf("\r\nReceive Date from PC and Send to Destination\r\n");
            USART2_printf("%s\r\n", USART_RX_BUF); // 通过lora发送出去
            memset(USART_RX_BUF, 0, USART_REC_LEN);
            USART_RX_STA = 0;
        }
    } // while

} // main

/**
 * @brief 系统时钟配置
 * @retval 无
 */
void SystemClock_Config(void)
{
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
    RCC_PeriphCLKInitTypeDef PeriphClkInit = {0};

    /** 配置主内部调节器输出电压
     */
    HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1);
    /** 初始化 RCC 振荡器，按照指定参数
     * 在 RCC_OscInitTypeDef 结构中配置。
     */
    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
    RCC_OscInitStruct.HSIState = RCC_HSI_ON;
    RCC_OscInitStruct.HSIDiv = RCC_HSI_DIV1;
    RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
    RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
    RCC_OscInitStruct.PLL.PLLM = RCC_PLLM_DIV1;
    RCC_OscInitStruct.PLL.PLLN = 8;
    RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
    RCC_OscInitStruct.PLL.PLLQ = RCC_PLLQ_DIV2;
    RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV2;
    if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
    {
        Error_Handler();
    }
    /** 初始化 CPU, AHB 和 APB 总线时钟
     */
    RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1;
    RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;

    if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
    {
        Error_Handler();
    }
    /** 初始化外围设备时钟
     */
    PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_USART1;
    PeriphClkInit.Usart1ClockSelection = RCC_USART1CLKSOURCE_PCLK1;
    if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit) != HAL_OK)
    {
        Error_Handler();
    }
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
 * @brief  发生错误时执行的函数。
 * @retval 无
 */
void Error_Handler(void)
{
    /* USER CODE BEGIN Error_Handler_Debug */
    /* 用户可以在此处添加自己的代码来报告 HAL 错误返回状态 */
    __disable_irq();
    while (1)
    {
    }
    /* USER CODE END Error_Handler_Debug */
}

#ifdef USE_FULL_ASSERT
/**
 * @brief  报告断言错误的源文件名和行号。
 * @param  file: 指向源文件名的指针
 * @param  line: 断言错误行号
 * @retval 无
 */
void assert_failed(uint8_t *file, uint32_t line)
{
    /* USER CODE BEGIN 6 */
    /* 用户可以在此处添加自己的代码来报告文件名和行号，
       例如：printf("错误的参数值: 文件 %s 第 %d 行\r\n", file, line) */
    /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */

/************************ (C) COPYRIGHT CSTX *****END OF FILE****/
