/**
 * @file main.c
 * @brief 统一的 WWSN 节点行为（簇头/正常/恶意）实现。
 *
 * 说明：
 * - 本文件融合了簇头、正常节点、恶意节点三份代码的核心逻辑。
 * - 通过编译期宏切换角色，运行期动态加入网络、分配节点 ID。
 * - 统一实现：路由发现与转发、数据采集与上报、监听统计、恶意行为注入。
 */

#include "main.h"
#include "usart.h"
#include "gpio.h"
#include "oled.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//========================== 编译期角色与功能开关 ==========================//
// 角色：1=簇头/汇聚节点（sink），0=普通节点
#ifndef NODE_ROLE_SINK
#define NODE_ROLE_SINK 0
#endif
// 传感器采集开关（DHT11）
#ifndef NODE_ENABLE_SENSOR
#define NODE_ENABLE_SENSOR 1
#endif
// WiFi/服务器上报开关（默认仅簇头开启）
#ifndef NODE_ENABLE_WIFI
#define NODE_ENABLE_WIFI NODE_ROLE_SINK
#endif

//========================== WiFi/服务器配置 ==========================//
#if NODE_ENABLE_WIFI
#ifndef ServerIP
#define ServerIP "192.168.31.121" // TCP 服务器地址
#endif
#ifndef Port
#define Port "60000" // TCP 端口
#endif
#ifndef SSID
#define SSID "Wireless Weak-link Network" // 路由器 SSID
#endif
#ifndef Password
#define Password "18239778101" // 路由器密码
#endif
#endif

//========================== WiFi/ ==========================//
#define LINK_MODE_AUTO 0 // 自动选择连接方式
#define LINK_MODE_WIFI 1 // 强制 WiFi 连接
#define LINK_MODE_SERIAL 2 // 连接模式
#define WIFI_CONNECT_TRY_MAX 3   // WiFi 连接尝试次数
#define SERVER_CONNECT_TRY_MAX 3 // TCP 服务器连接尝试次数

#if NODE_ENABLE_SENSOR
#include "dht11.h"
#endif

#if NODE_ENABLE_WIFI
#include "mqtt.h"
#include "esp8266.h"
#endif

//========================== 协议常量/控制码 ==========================//
#define SDATA "ToggleLED\r\n"
#define ROUTE_REQUEST 0x01 // 路由请求
#define ROUTE_REPLY 0x02   // 路由回复
#define DATA_PACKET 0x03   // 数据包
#define ACK_PACKET 0x04    // ACK 确认
#define JOIN_REQUEST 0x10  // 加入网络请求
#define JOIN_ASSIGN 0x11   // 加入网络分配结果
#define CONTROL_PACKET 0x20 // 控制命令
#define CONTROL_ACK 0x21    // 控制命令 ACK
#define STATUS_PACKET 0x22  // 状态上报

//========================== 表大小/超时/重试参数 ==========================//
#define ROUTING_TABLE_SIZE_INITIAL 10 // 路由表初始大小
#define SNIFF_TABLE_SIZE_INITIAL 0    // 监听表初始大小
#define ROUTE_REQ_CACHE_SIZE 8        // 路由请求去重缓存大小
#define ROUTE_REQ_TIMEOUT 10000       // 路由请求去重有效期(ms)
#define ROUTE_REQ_RETRY 5000          // 路由请求重试间隔(ms)
#define ROUTE_MAX_HOPS 8              // 路由请求/回复最大跳数
#define ROUTE_ENTRY_TIMEOUT 60000     // 路由表条目超时(ms)
#define ROUTE_PRUNE_INTERVAL 5000     // 路由表清理周期(ms)
#define CONTROL_CACHE_SIZE 8          // 控制命令去重缓存大小
#define CONTROL_CACHE_TIMEOUT 10000   // 控制命令去重有效期(ms)
#define STATUS_REPORT_INTERVAL 15000  // 状态上报周期(ms)
#define JOIN_REQUEST_INTERVAL 3000    // 加入网络重试间隔(ms)
#define ACK_MISS_THRESHOLD 5          // 连续未收到 ACK 的阈值

//========================== 网络与节点参数 ==========================//
#define NODE_ID_UNASSIGNED 0xFF // 未分配 ID 标记
#define TARGET_ID 1             // 汇聚节点 ID
#define MAX_NODES 32            // 汇聚节点可管理的最大节点数量

//========================== 恶意行为参数 ==========================//
#define MALICIOUS_PROB 30       // 成为恶意节点概率(%)
#define MALICIOUS_DROP_RATE 30  // 恶意节点丢包概率(%)

//========================== 控制命令常量 ==========================//
#define CMD_MODE 1
#define CMD_ROUND 2
#define CMD_ONOFF 3
#define CMD_ROUTE 4
#define CMD_DROP 5

#define CTRL_STR_MAX 40

//========================== LoRa 地址与信道 ==========================//
#define MacH 0xFF
#define MacL 0xFF
#define channelID 0x09

//========================== 数据包结构 ==========================//
// 注意：此结构与原有三份代码保持一致，确保协议兼容。
typedef struct
{
    uint8_t destMacH;
    uint8_t destMacL;
    uint8_t destchanID;
    uint8_t sourceMacH;
    uint8_t sourceMacL;
    uint8_t sourceID;
    uint8_t forwardID;
    uint8_t forwardtoID;
    uint8_t destID;
    uint8_t protocol;
    uint8_t ID;
    char data[40];
} DataPacket;

//========================== 路由表结构 ==========================//
typedef struct
{
    uint8_t destID;
    uint8_t nextHopID;
    uint8_t macHigh;
    uint8_t macLow;
    uint32_t lastSeen;
    uint8_t hop;
    int16_t rssi;
    int16_t noise;
} RoutingEntry;

//========================== 监听表结构 ==========================//
typedef struct
{
    uint32_t lastSniffTime;
    uint8_t sourceID;
    uint8_t snifferID;
    uint8_t forwardCount;
    uint8_t sourceCount;
    uint8_t ackCount;
    uint8_t routeReqCount;
    uint8_t routeRepCount;
    uint8_t lastRSSI;
} SnifferTable;

//========================== 路由请求去重缓存结构 ==========================//
typedef struct
{
    uint8_t sourceID;
    uint8_t requestID;
    uint32_t lastSeen;
} RouteReqCache;

typedef struct
{
    uint8_t sourceID;
    uint8_t seq;
    uint8_t cmd;
    uint32_t lastSeen;
} ControlCache;

#if NODE_ROLE_SINK
//========================== 簇头节点登记表 ==========================//
typedef struct
{
    uint32_t uid;
    uint8_t nodeID;
    uint32_t lastSeen;
} NodeRegistry;
#endif

//========================== 函数声明 ==========================//
void SystemClock_Config(void);

// 本文件内部函数
static void configureModule(void);
static int getEnvirRSSI(void);
static void addRoutingEntry(uint8_t destID, uint8_t nextHopID, uint8_t macHigh, uint8_t macLow, uint8_t hop, int16_t rssi, int16_t noise);
static void deleteRoutingEntry(uint8_t routeIndex);
static int findRoute(uint8_t destID);
static void printRoutingTable(void);
static void pruneRoutingTable(void);
static int isBetterRoute(uint8_t newHop, int16_t newRssi, uint8_t oldHop, int16_t oldRssi);

static void sendJoinRequest(void);
static void sendJoinAssign(uint32_t uid, uint8_t assignedID);
static void sendRouteRequest(uint8_t destID);
static void sendRouteReply(uint8_t requestorID, uint8_t replySourceID, uint8_t nextHopID);
static void sendAckPacket(uint8_t destID, uint8_t macH, uint8_t macL);
static void sendDataPacket(DataPacket *packet);
static void sendControlPacket(uint8_t destID, uint8_t seq, uint8_t cmd, int32_t p1, int32_t p2);
static void sendControlAckPacket(uint8_t seq, uint8_t cmd, uint8_t status);
static void sendControlAckToServer(uint8_t seq, uint8_t cmd, uint8_t status);
static void sendStatusPacket(void);
static void processStatusPacket(DataPacket *packet);

static void handleReceivedPacket(DataPacket *packet);
static void processJoinRequest(DataPacket *packet);
static void processJoinAssign(DataPacket *packet);
static void processRouteRequest(DataPacket *packet);
static void processRouteReply(DataPacket *packet);
static void processDataPacket(DataPacket *packet);
static void processAckPacket(DataPacket *packet);
static void processControlPacket(DataPacket *packet);
static void processControlAckPacket(DataPacket *packet);

static void sniff(DataPacket *packet);
static int findSniffID(uint8_t forwardID);
static void sanitizeData(uint8_t *data, size_t len);
static void restoreData(uint8_t *data, size_t len);
static void writeAsciiData(char *data, size_t len, const char *str);
static uint8_t cmdFromString(const char *cmd);
static const char *cmdToString(uint8_t cmd);
static int parseControlString(const char *str, uint8_t *seq, uint8_t *cmd, int32_t *p1, int32_t *p2);
static uint8_t applyControlCommand(uint8_t cmd, int32_t p1, int32_t p2);
static void fabricateSniffData(uint8_t *data);
static void seedRandom(void);
static uint32_t getDeviceUID(void);
static void initDeviceUID(void);
static void decideMalicious(void);
static void updateOnOff(void);
static int isDuplicateRouteReq(uint8_t sourceID, uint8_t reqID);
static void initRouteReqCache(void);
static int isDuplicateControl(uint8_t sourceID, uint8_t seq, uint8_t cmd);
static void initControlCache(void);
static void updateNodeDisplay(void);
static void sendSensorData(void);

#if NODE_ENABLE_WIFI
static void connectServer(void);
#endif

#if NODE_ROLE_SINK
static uint8_t assignNodeID(uint32_t uid);
static void handleTcpCommandBuffer(const uint8_t *buf);
#endif

//========================== 全局运行参数与状态 ==========================//
#if NODE_ROLE_SINK
uint8_t nodeID = TARGET_ID;
#else
uint8_t nodeID = NODE_ID_UNASSIGNED;
#endif

uint8_t targetID = TARGET_ID; // 汇聚节点 ID
uint32_t roundTime = 20000;   // 采集/发送周期(ms)

uint8_t maliciousType = 0; // 1=丢包 2=伪造监听 3=混合
uint8_t isMalicious = 0;   // 是否为恶意节点
uint8_t onoffEnabled = 1;  // 是否开启 on-off 攻击
uint8_t onoffOn = 1;       // on-off 当前状态
uint8_t onoffCount = 0;    // on-off 计数
uint8_t dropPolicy = 0;    // 0=normal,1=always drop,2=random drop
uint8_t dropRate = 0;      // 0-100 for random drop

unsigned char key = 0;     // 寄存器返回码
unsigned char RSSIkey = 0; // RSSI 读取返回码
unsigned char disOLED[24]; // OLED 显示缓冲
char nodeIDStr[8];         // 节点 ID 字符串

RoutingEntry *routingTable = NULL;
int routingTableSize = ROUTING_TABLE_SIZE_INITIAL;
int routingTableCount = 0;

SnifferTable *sniffTable = NULL;
int sniffTableSize = SNIFF_TABLE_SIZE_INITIAL;
int sniffTableCount = 0;
uint8_t sniffTableSendID = 0; // 监听表轮询发送索引

RouteReqCache routeReqCache[ROUTE_REQ_CACHE_SIZE]; // 去重缓存
ControlCache controlCache[CONTROL_CACHE_SIZE];

unsigned char packetBUF[sizeof(DataPacket)]; // 串口发送缓冲

uint32_t previousMillisA0 = 0; // 传感器发送计时
uint32_t previousRouteReq = 0; // 路由请求计时
uint32_t previousJoinReq = 0;  // 加入请求计时
uint32_t lastRoutePrune = 0;   // 路由表清理计时
uint32_t previousStatusReport = 0; // 状态上报计时
uint8_t previousNotGetACK = 0; // ACK 未收到累计次数
uint8_t sendRoutRequest = 0;   // 路由请求进行中标记
uint8_t getRoutReplay = 0;     // 路由回复标记
uint8_t RSSI = 0;              // 最近 RSSI
uint8_t packetID = 1;          // 数据包 ID 递增
uint32_t deviceUID = 0;        // 节点唯一标识
char deviceUIDStr[9];          // UID 十六进制字符串
uint8_t pendingCtrlAckValid = 0;
uint8_t pendingCtrlAckSeq = 0;
uint8_t pendingCtrlAckCmd = 0;
uint8_t pendingCtrlAckStatus = 0;

#if NODE_ENABLE_WIFI
unsigned char servernotok = 1; // 服务器连接状态
uint8_t res = 1;               // WiFi 连接状态
uint8_t linkMode = LINK_MODE_AUTO; // 0=自动 1=WiFi 2=串口
#endif

#if NODE_ROLE_SINK
NodeRegistry nodeRegistry[MAX_NODES];
uint8_t nodeRegistryCount = 0;
uint8_t nextNodeID = 2; // 从 2 开始分配（1 给汇聚节点）
#endif

// LoRa 模块寄存器配置与读取缓冲
unsigned char cscxReg[10] = {0xC0, 0x00, 0x07, 0x10, 0x02, 0x01, 0x61, 0x20, 0x09, 0xD0};
unsigned char csrevReg[12] = {0xC1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/**
 * @brief 配置 LoRa 模块地址与信道。
 * 这里只写回本节点地址，其他配置沿用模块默认/原项目设定。
 */
static void configureModule(void)
{
    cscxReg[3] = MacH;
    cscxReg[4] = MacL;
}

/**
 * @brief 读取当前信道环境噪声 RSSI，并打印调试信息。
 */
static int getEnvirRSSI(void)
{
    uint8_t envirRssi = 0;
    if (HAL_GPIO_ReadPin(M0_GPIO_Port, M0_Pin) == 0 && HAL_GPIO_ReadPin(M1_GPIO_Port, M1_Pin) == 0)
    {
        unsigned char cscxRSSIreq2[6] = {0xC0, 0xC1, 0xC2, 0xC3, 0x00, 0x01};
        unsigned char cscxRSSI[4] = {0x00, 0x00, 0x00, 0x00};
        CS_Reg_Send_Data(cscxRSSIreq2, sizeof(cscxRSSIreq2));
        HAL_Delay(500);
        cstx_reg_Receive_Data(cscxRSSI, &RSSIkey);
        envirRssi = cscxRSSI[3];
        printf("\r\ncurrentChannelNoise: -%ddBm\r\n", 256 - envirRssi);
        printf("\r\ncurrentChannelSNR: %ddB\r\n", RSSI - cscxRSSI[3]);
    }
    return envirRssi;
}

/**
 * @brief 向路由表添加一条路由信息（自动扩容）。
 */
static void addRoutingEntry(uint8_t destID, uint8_t nextHopID, uint8_t macHigh, uint8_t macLow,
                            uint8_t hop, int16_t rssi, int16_t noise)
{
    uint32_t now = HAL_GetTick();
    for (int i = 0; i < routingTableCount; i++)
    {
        if (routingTable[i].destID == destID)
        {
            if (isBetterRoute(hop, rssi, routingTable[i].hop, routingTable[i].rssi))
            {
                routingTable[i].nextHopID = nextHopID;
                routingTable[i].macHigh = macHigh;
                routingTable[i].macLow = macLow;
                routingTable[i].hop = hop;
                routingTable[i].rssi = rssi;
                routingTable[i].noise = noise;
            }
            routingTable[i].lastSeen = now;
            return;
        }
    }
    if (routingTableCount >= routingTableSize)
    {
        routingTableSize += 2;
        routingTable = (RoutingEntry *)realloc(routingTable, routingTableSize * sizeof(RoutingEntry));
    }
    routingTable[routingTableCount].destID = destID;
    routingTable[routingTableCount].nextHopID = nextHopID;
    routingTable[routingTableCount].macHigh = macHigh;
    routingTable[routingTableCount].macLow = macLow;
    routingTable[routingTableCount].lastSeen = now;
    routingTable[routingTableCount].hop = hop;
    routingTable[routingTableCount].rssi = rssi;
    routingTable[routingTableCount].noise = noise;
    routingTableCount++;
}

/**
 * @brief 删除路由表中指定索引的条目。
 */
static void deleteRoutingEntry(uint8_t routeIndex)
{
    for (int j = routeIndex; j < routingTableCount - 1; j++)
    {
        routingTable[j] = routingTable[j + 1];
    }
    if (routingTableCount > 0)
    {
        routingTableCount--;
    }
}

/**
 * @brief 查找目的节点的下一跳路由。
 * @return 路由表索引，未找到则返回 -1。
 */
static int findRoute(uint8_t destID)
{
    uint32_t now = HAL_GetTick();
    for (int i = 0; i < routingTableCount;)
    {
        if (routingTable[i].destID != nodeID &&
            now - routingTable[i].lastSeen > ROUTE_ENTRY_TIMEOUT)
        {
            deleteRoutingEntry((uint8_t)i);
            continue;
        }
        if (routingTable[i].destID == destID && routingTable[i].nextHopID != nodeID)
        {
            routingTable[i].lastSeen = now;
            return i;
        }
        i++;
    }
    return -1;
}

static void pruneRoutingTable(void)
{
    uint32_t now = HAL_GetTick();
    for (int i = 0; i < routingTableCount;)
    {
        if (routingTable[i].destID != nodeID &&
            now - routingTable[i].lastSeen > ROUTE_ENTRY_TIMEOUT)
        {
            deleteRoutingEntry((uint8_t)i);
            continue;
        }
        i++;
    }
}

static int isBetterRoute(uint8_t newHop, int16_t newRssi, uint8_t oldHop, int16_t oldRssi)
{
    if (newHop < oldHop)
    {
        return 1;
    }
    if (newHop > oldHop)
    {
        return 0;
    }
    if (newRssi > oldRssi)
    {
        return 1;
    }
    return 0;
}

/**
 * @brief 打印当前路由表。
 */
static void printRoutingTable(void)
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
 * @brief 通过串口透明模式发送数据包。
 */
static void sendDataPacket(DataPacket *packet)
{
    memcpy(packetBUF, packet, sizeof(DataPacket));
    USART2_printf("%s\n", packetBUF);
}

/**
 * @brief 发送加入网络请求，携带本节点 UID。
 * 仅在 nodeID 未分配时触发。
 */
static void sendJoinRequest(void)
{
    if (nodeID != NODE_ID_UNASSIGNED)
    {
        return;
    }
    DataPacket packet;
    packet.ID = packetID++;
    packet.destMacH = 0xFF;
    packet.destMacL = 0xFF;
    packet.destchanID = channelID;
    packet.sourceMacH = MacH;
    packet.sourceMacL = MacL;
    packet.sourceID = NODE_ID_UNASSIGNED;
    packet.forwardID = NODE_ID_UNASSIGNED;
    packet.forwardtoID = 0xFF;
    packet.destID = TARGET_ID;
    packet.protocol = JOIN_REQUEST;
    memset(packet.data, 0xFF, sizeof(packet.data));
    memcpy(packet.data, deviceUIDStr, 8);
    sendDataPacket(&packet);
}

/**
 * @brief 簇头发送加入分配结果，携带 UID 与分配的节点 ID。
 */
static void sendJoinAssign(uint32_t uid, uint8_t assignedID)
{
    DataPacket packet;
    char uidStr[9];
    char idStr[3];
    packet.ID = packetID++;
    packet.destMacH = 0xFF;
    packet.destMacL = 0xFF;
    packet.destchanID = channelID;
    packet.sourceMacH = MacH;
    packet.sourceMacL = MacL;
    packet.sourceID = nodeID;
    packet.forwardID = nodeID;
    packet.forwardtoID = 0xFF;
    packet.destID = NODE_ID_UNASSIGNED;
    packet.protocol = JOIN_ASSIGN;
    memset(packet.data, 0xFF, sizeof(packet.data));
    // data[0..7]=UID(ASCII)，data[8..9]=ID(ASCII)
    snprintf(uidStr, sizeof(uidStr), "%08lX", (unsigned long)uid);
    snprintf(idStr, sizeof(idStr), "%02X", assignedID);
    memcpy(packet.data, uidStr, 8);
    memcpy(&packet.data[8], idStr, 2);
    sendDataPacket(&packet);
}

/**
 * @brief 发送路由请求（广播），用于寻找到目标节点的路径。
 */
static void sendRouteRequest(uint8_t destID)
{
    if (nodeID == NODE_ID_UNASSIGNED)
    {
        return;
    }
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
    memset(packet.data, 0xFF, sizeof(packet.data));
    packet.data[0] = 1;
    sendDataPacket(&packet);
}

/**
 * @brief 发送路由回复。
 * @param requestorID 路由请求发起者 ID
 * @param replySourceID 路由终点（通常为 destID）
 * @param nextHopID 回复转发的下一跳
 */
static void sendRouteReply(uint8_t requestorID, uint8_t replySourceID, uint8_t nextHopID)
{
    DataPacket packet;
    packet.ID = packetID++;
    packet.destMacH = 0xFF;
    packet.destMacL = 0xFF;
    packet.destchanID = channelID;
    packet.sourceMacH = MacH;
    packet.sourceMacL = MacL;
    packet.sourceID = replySourceID;
    packet.forwardID = nodeID;
    packet.forwardtoID = nextHopID;
    packet.destID = requestorID;
    packet.protocol = ROUTE_REPLY;
    memset(packet.data, 0xFF, sizeof(packet.data));
    packet.data[0] = 1;
    sendDataPacket(&packet);
}

/**
 * @brief 发送 ACK 确认包。
 */
static void sendAckPacket(uint8_t destID, uint8_t macH, uint8_t macL)
{
    DataPacket packet;
    packet.ID = packetID++;
    packet.destMacH = macH;
    packet.destMacL = macL;
    packet.destchanID = channelID;
    packet.sourceMacH = MacH;
    packet.sourceMacL = MacL;
    packet.sourceID = nodeID;
    packet.forwardID = nodeID;
    packet.forwardtoID = destID;
    packet.destID = destID;
    packet.protocol = ACK_PACKET;
    memset(packet.data, 0xFF, sizeof(packet.data));
    sendDataPacket(&packet);
}

static void sendControlPacket(uint8_t destID, uint8_t seq, uint8_t cmd, int32_t p1, int32_t p2)
{
    DataPacket packet;
    char cmdStr[CTRL_STR_MAX + 1];
    int routeIndex = -1;

    if (nodeID == NODE_ID_UNASSIGNED)
    {
        return;
    }

    snprintf(cmdStr, sizeof(cmdStr), "C,%u,%s,%ld,%ld",
             (unsigned int)seq,
             cmdToString(cmd),
             (long)p1,
             (long)p2);

    packet.ID = packetID++;
    packet.destMacH = 0xFF;
    packet.destMacL = 0xFF;
    packet.destchanID = channelID;
    packet.sourceMacH = MacH;
    packet.sourceMacL = MacL;
    packet.sourceID = nodeID;
    packet.forwardID = nodeID;
    packet.destID = destID;
    packet.protocol = CONTROL_PACKET;

    if (destID == 0xFF)
    {
        packet.forwardtoID = 0xFF;
    }
    else
    {
        routeIndex = findRoute(destID);
        packet.forwardtoID = (routeIndex != -1) ? routingTable[routeIndex].nextHopID : 0xFF;
    }

    writeAsciiData(packet.data, sizeof(packet.data), cmdStr);
    sendDataPacket(&packet);
}

static void sendControlAckPacket(uint8_t seq, uint8_t cmd, uint8_t status)
{
    DataPacket packet;
    char ackStr[CTRL_STR_MAX + 1];
    int routeIndex = -1;

    if (nodeID == NODE_ID_UNASSIGNED)
    {
        return;
    }

    snprintf(ackStr, sizeof(ackStr), "A,%u,%s,%u,%u",
             (unsigned int)seq,
             cmdToString(cmd),
             (unsigned int)status,
             (unsigned int)nodeID);

    packet.ID = packetID++;
    packet.destMacH = 0xFF;
    packet.destMacL = 0xFF;
    packet.destchanID = channelID;
    packet.sourceMacH = MacH;
    packet.sourceMacL = MacL;
    packet.sourceID = nodeID;
    packet.forwardID = nodeID;
    packet.destID = targetID;
    packet.protocol = CONTROL_ACK;

    routeIndex = findRoute(targetID);
    if (routeIndex == -1 && nodeID != targetID)
    {
        pendingCtrlAckValid = 1;
        pendingCtrlAckSeq = seq;
        pendingCtrlAckCmd = cmd;
        pendingCtrlAckStatus = status;
        sendRouteRequest(targetID);
        previousRouteReq = HAL_GetTick();
        sendRoutRequest = 1;
        getRoutReplay = 0;
        return;
    }
    packet.forwardtoID = (routeIndex != -1) ? routingTable[routeIndex].nextHopID : 0xFF;

    writeAsciiData(packet.data, sizeof(packet.data), ackStr);
    sendDataPacket(&packet);
}

static void sendControlAckToServer(uint8_t seq, uint8_t cmd, uint8_t status)
{
#if NODE_ROLE_SINK
    printf("ACK,A,%u,%s,%u,%u\r\n",
           (unsigned int)seq,
           cmdToString(cmd),
           (unsigned int)status,
           (unsigned int)nodeID);
#else
    (void)seq;
    (void)cmd;
    (void)status;
#endif
}

static void sendStatusPacket(void)
{
    DataPacket packet;
    char statusStr[CTRL_STR_MAX + 1];
    int routeIndex = -1;

    if (nodeID == NODE_ID_UNASSIGNED)
    {
        return;
    }

    if (nodeID == targetID)
    {
        printf("STAT,%u,%lu,%u,%u,%u,%u,%u,%u\r\n",
               (unsigned int)nodeID,
               (unsigned long)roundTime,
               (unsigned int)onoffEnabled,
               (unsigned int)onoffOn,
               (unsigned int)isMalicious,
               (unsigned int)maliciousType,
               (unsigned int)dropPolicy,
               (unsigned int)dropRate);
        return;
    }

    snprintf(statusStr, sizeof(statusStr), "S,%u,%lu,%u,%u,%u,%u,%u,%u",
             (unsigned int)nodeID,
             (unsigned long)roundTime,
             (unsigned int)onoffEnabled,
             (unsigned int)onoffOn,
             (unsigned int)isMalicious,
             (unsigned int)maliciousType,
             (unsigned int)dropPolicy,
             (unsigned int)dropRate);

    packet.ID = packetID++;
    packet.destMacH = 0xFF;
    packet.destMacL = 0xFF;
    packet.destchanID = channelID;
    packet.sourceMacH = MacH;
    packet.sourceMacL = MacL;
    packet.sourceID = nodeID;
    packet.forwardID = nodeID;
    packet.destID = targetID;
    packet.protocol = STATUS_PACKET;

    routeIndex = findRoute(targetID);
    packet.forwardtoID = (routeIndex != -1) ? routingTable[routeIndex].nextHopID : 0xFF;

    writeAsciiData(packet.data, sizeof(packet.data), statusStr);
    sendDataPacket(&packet);
}

/**
 * @brief 按协议类型分发处理接收的数据包。
 */
static void handleReceivedPacket(DataPacket *packet)
{
    switch (packet->protocol)
    {
    case JOIN_REQUEST:
        processJoinRequest(packet);
        break;
    case JOIN_ASSIGN:
        processJoinAssign(packet);
        break;
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
    case STATUS_PACKET:
        processStatusPacket(packet);
        break;
    case CONTROL_PACKET:
        processControlPacket(packet);
        break;
    case CONTROL_ACK:
        processControlAckPacket(packet);
        break;
    default:
        break;
    }
}

/**
 * @brief 簇头处理加入请求并分配 ID。
 */
static void processJoinRequest(DataPacket *packet)
{
#if NODE_ROLE_SINK
    char uidStr[9];
    uint32_t uid = 0;
    // UID 以 8 字节 ASCII 十六进制字符串传输
    // 校验是否是发给自己的分配结果
    memcpy(uidStr, packet->data, 8);
    uidStr[8] = '\0';
    uid = (uint32_t)strtoul(uidStr, NULL, 16);
    if (uid == 0)
    {
        return;
    }
    // 为新节点分配 ID
    uint8_t assignedID = assignNodeID(uid);
    if (assignedID != NODE_ID_UNASSIGNED)
    {
        sendJoinAssign(uid, assignedID);
    }
#else
    (void)packet;
#endif
}

/**
 * @brief 普通节点接收加入分配结果，完成 ID 设定与路由初始化。
 */
static void processJoinAssign(DataPacket *packet)
{
    if (NODE_ROLE_SINK || nodeID != NODE_ID_UNASSIGNED)
    {
        return;
    }
    char uidStr[9];
    char idStr[3];
    uint8_t assignedID = NODE_ID_UNASSIGNED;
    memcpy(uidStr, packet->data, 8);
    uidStr[8] = '\0';
    if (strncmp(uidStr, deviceUIDStr, 8) != 0)
    {
        return;
    }
    // 解析分配的 ID（ASCII 十六进制）
    memcpy(idStr, &packet->data[8], 2);
    idStr[2] = '\0';
    assignedID = (uint8_t)strtoul(idStr, NULL, 16);
    if (assignedID == NODE_ID_UNASSIGNED)
    {
        return;
    }
    // 完成入网：设置 ID、建立自路由、更新显示并初始化恶意策略
    nodeID = assignedID;
    addRoutingEntry(nodeID, nodeID, MacH, MacL, 0, 0, 0);
    updateNodeDisplay();
    seedRandom();
    decideMalicious();
    // 加入完成后主动发起路由查询，寻找到汇聚节点的路径
    sendRouteRequest(targetID);
    previousRouteReq = HAL_GetTick();
    sendRoutRequest = 1;
    getRoutReplay = 0;
}

/**
 * @brief 处理路由请求：去重、学习逆向路由、回复或继续转发。
 */
static void processRouteRequest(DataPacket *packet)
{
    uint8_t hop = 0;
    uint8_t hopToSource = 0;
    if (!NODE_ROLE_SINK && nodeID == NODE_ID_UNASSIGNED)
    {
        return;
    }
    if (isDuplicateRouteReq(packet->sourceID, packet->ID))
    {
        return;
    }

    if (packet->data[0] > 0)
    {
        hopToSource = (uint8_t)(packet->data[0] - 1);
    }

    // 学习源节点的逆向路径，便于后续回复
    if (packet->sourceID != nodeID)
    {
        addRoutingEntry(packet->sourceID, packet->forwardID, packet->sourceMacH, packet->sourceMacL,
                        hopToSource, (int16_t)RSSI - 256, 0);
    }

    // 如果本节点就是目的节点，直接回复路由
    if (nodeID == packet->destID)
    {
        sendRouteReply(packet->sourceID, packet->destID, packet->forwardID);
        return;
    }

    // 若已有到目的节点的路由，也可以直接回复
    int routeIndex = findRoute(packet->destID);
    if (routeIndex != -1)
    {
        sendRouteReply(packet->sourceID, packet->destID, packet->forwardID);
        return;
    }

    if (packet->data[0] > 0)
    {
        hop = (uint8_t)(packet->data[0] - 1);
    }
    if (hop >= ROUTE_MAX_HOPS)
    {
        return;
    }
    hop++;

    // 否则继续广播转发路由请求
    packet->destMacH = 0xFF;
    packet->destMacL = 0xFF;
    packet->destchanID = channelID;
    packet->sourceMacH = MacH;
    packet->sourceMacL = MacL;
    packet->forwardID = nodeID;
    packet->forwardtoID = 0xFF;
    packet->data[0] = (uint8_t)(hop + 1);
    sanitizeData((uint8_t *)packet->data, sizeof(packet->data));
    sendDataPacket(packet);
}

/**
 * @brief 处理路由回复：更新路由并尝试向请求源转发。
 */
static void processRouteReply(DataPacket *packet)
{
    uint8_t hop = 0;
    uint8_t hopToSource = 0;
    if (!NODE_ROLE_SINK && nodeID == NODE_ID_UNASSIGNED)
    {
        return;
    }

    if (packet->data[0] > 0)
    {
        hopToSource = (uint8_t)(packet->data[0] - 1);
    }

    // 更新到回复源的路由
    addRoutingEntry(packet->sourceID, packet->forwardID, packet->sourceMacH, packet->sourceMacL,
                    hopToSource, (int16_t)RSSI - 256, 0);

    // 如果回复是发给本节点，标记路由已建立
    if (packet->destID == nodeID)
    {
        getRoutReplay = 1;
        sendRoutRequest = 0;
        return;
    }

    // 尝试向请求源继续转发回复
    int routeIndex = findRoute(packet->destID);
    if (routeIndex == -1)
    {
        return;
    }

    if (packet->data[0] > 0)
    {
        hop = (uint8_t)(packet->data[0] - 1);
    }
    if (hop >= ROUTE_MAX_HOPS)
    {
        return;
    }
    hop++;

    packet->destMacH = 0xFF;
    packet->destMacL = 0xFF;
    packet->destchanID = channelID;
    packet->sourceMacH = MacH;
    packet->sourceMacL = MacL;
    packet->forwardID = nodeID;
    packet->forwardtoID = routingTable[routeIndex].nextHopID;
    packet->data[0] = (uint8_t)(hop + 1);
    sanitizeData((uint8_t *)packet->data, sizeof(packet->data));
    sendDataPacket(packet);
}

/**
 * @brief 处理数据包：
 * - 若为终点：显示数据、ACK、可上报服务器
 * - 若为中继：ACK + 依据路由继续转发（可注入恶意行为）
 */
static void processDataPacket(DataPacket *packet)
{
    if (!NODE_ROLE_SINK && nodeID == NODE_ID_UNASSIGNED)
    {
        return;
    }

    if (packet->destID == nodeID)
    {
        memset(disOLED, 0, sizeof(disOLED));
        sprintf((char *)disOLED, "T:%d.%dC H:%d.%dR", packet->data[0], packet->data[1], packet->data[2], packet->data[3]);
        OLED_ShowString(0, 6, disOLED);
        sendAckPacket(packet->forwardID, packet->sourceMacH, packet->sourceMacL);
        getEnvirRSSI();

#if NODE_ENABLE_WIFI
        if ((servernotok || res) && linkMode != LINK_MODE_SERIAL)
        {
            connectServer();
        }
        if (!servernotok && linkMode == LINK_MODE_WIFI)
        {
            OLED_ShowString(0, 2, "Send SERVER OK ");
        }
#endif
        return;
    }

    // 非终点：先 ACK，再尝试转发
    sendAckPacket(packet->forwardID, packet->sourceMacH, packet->sourceMacL);
    uint8_t envirRSSI = getEnvirRSSI();

    if (dropPolicy == 1)
    {
        return;
    }
    if (dropPolicy == 2 && (rand() % 100 < dropRate))
    {
        return;
    }

    // 恶意节点行为注入：丢包或伪造监听数据
    if (isMalicious && ((onoffEnabled && onoffOn) || !onoffEnabled))
    {
        if (maliciousType == 1)
        {
            return;
        }
        if (maliciousType == 3 && (rand() % 100 < MALICIOUS_DROP_RATE))
        {
            return;
        }
        if (maliciousType == 2 || maliciousType == 3)
        {
            fabricateSniffData((uint8_t *)packet->data);
        }
    }

    // 正常转发：查到达汇聚节点的路径
    int routeIndex = findRoute(targetID);
    if (routeIndex != -1)
    {
        packet->destMacH = 0xFF;
        packet->destMacL = 0xFF;
        packet->destchanID = channelID;
        packet->sourceMacH = MacH;
        packet->sourceMacL = MacL;
        packet->forwardID = nodeID;
        packet->forwardtoID = routingTable[routeIndex].nextHopID;

        // 记录路径与信号强度/噪声（沿用原项目数据格式）
        for (int i = 28; i >= 0; i = i + 3)
        {
            if (packet->data[i] == 0)
            {
                packet->data[i] = nodeID;
                packet->data[i + 1] = RSSI;
                packet->data[i + 2] = envirRSSI;
                break;
            }
        }
        sanitizeData((uint8_t *)packet->data, sizeof(packet->data));
        sendDataPacket(packet);
    }
    else
    {
        // 未找到路径，触发路由请求
        sendRouteRequest(targetID);
        previousRouteReq = HAL_GetTick();
        sendRoutRequest = 1;
        getRoutReplay = 0;
    }
}

/**
 * @brief 处理 ACK：重置连续未 ACK 计数。
 */
static void processAckPacket(DataPacket *packet)
{
    (void)packet;
    previousNotGetACK = 0;
}

static void processControlPacket(DataPacket *packet)
{
    char buf[CTRL_STR_MAX + 1];
    uint8_t seq = 0;
    uint8_t cmd = 0;
    int32_t p1 = 0;
    int32_t p2 = 0;
    uint8_t status = 0;

    if (!NODE_ROLE_SINK && nodeID == NODE_ID_UNASSIGNED)
    {
        return;
    }

    if (packet->destID != nodeID && packet->destID != 0xFF)
    {
        if (packet->forwardtoID != nodeID)
        {
            return;
        }
        int routeIndex = findRoute(packet->destID);
        if (routeIndex != -1)
        {
            packet->destMacH = 0xFF;
            packet->destMacL = 0xFF;
            packet->destchanID = channelID;
            packet->sourceMacH = MacH;
            packet->sourceMacL = MacL;
            packet->forwardID = nodeID;
            packet->forwardtoID = routingTable[routeIndex].nextHopID;
            sanitizeData((uint8_t *)packet->data, sizeof(packet->data));
            sendDataPacket(packet);
        }
        return;
    }

    memcpy(buf, packet->data, CTRL_STR_MAX);
    buf[CTRL_STR_MAX] = '\0';
    if (!parseControlString(buf, &seq, &cmd, &p1, &p2))
    {
        return;
    }

    if (isDuplicateControl(packet->sourceID, seq, cmd))
    {
        sendControlAckPacket(seq, cmd, 1);
        return;
    }

    status = applyControlCommand(cmd, p1, p2);
    sendControlAckPacket(seq, cmd, status);
}

static void processControlAckPacket(DataPacket *packet)
{
#if NODE_ROLE_SINK
    char buf[CTRL_STR_MAX + 1];
    memcpy(buf, packet->data, CTRL_STR_MAX);
    buf[CTRL_STR_MAX] = '\0';
    printf("ACK,%s\r\n", buf);
#else
    if (packet->forwardtoID != nodeID)
    {
        return;
    }
    if (packet->destID != targetID)
    {
        return;
    }
    int routeIndex = findRoute(targetID);
    if (routeIndex == -1)
    {
        return;
    }
    packet->destMacH = 0xFF;
    packet->destMacL = 0xFF;
    packet->destchanID = channelID;
    packet->sourceMacH = MacH;
    packet->sourceMacL = MacL;
    packet->forwardID = nodeID;
    packet->forwardtoID = routingTable[routeIndex].nextHopID;
    sanitizeData((uint8_t *)packet->data, sizeof(packet->data));
    sendDataPacket(packet);
#endif
}

static void processStatusPacket(DataPacket *packet)
{
    if (!NODE_ROLE_SINK && nodeID == NODE_ID_UNASSIGNED)
    {
        return;
    }

    if (packet->destID != nodeID)
    {
        int routeIndex = findRoute(packet->destID);
        if (routeIndex != -1)
        {
            packet->destMacH = 0xFF;
            packet->destMacL = 0xFF;
            packet->destchanID = channelID;
            packet->sourceMacH = MacH;
            packet->sourceMacL = MacL;
            packet->forwardID = nodeID;
            packet->forwardtoID = routingTable[routeIndex].nextHopID;
            sanitizeData((uint8_t *)packet->data, sizeof(packet->data));
            sendDataPacket(packet);
        }
        return;
    }

    if (NODE_ROLE_SINK)
    {
        char buf[CTRL_STR_MAX + 1];
        memcpy(buf, packet->data, CTRL_STR_MAX);
        buf[CTRL_STR_MAX] = '\0';
        printf("STAT,%s\r\n", buf);
    }
}

/**
 * @brief 监听网络中的数据包并统计行为特征。
 * 监听表用于观察转发、源包、ACK、路由行为等。
 */
static void sniff(DataPacket *packet)
{
    // 控制/加入包不计入监听统计
    if (packet->protocol == JOIN_REQUEST || packet->protocol == JOIN_ASSIGN ||
        packet->protocol == CONTROL_PACKET || packet->protocol == CONTROL_ACK ||
        packet->protocol == STATUS_PACKET)
    {
        return;
    }

    if (sniffTableCount >= sniffTableSize)
    {
        sniffTableSize += 1;
        sniffTable = (SnifferTable *)realloc(sniffTable, sniffTableSize * sizeof(SnifferTable));
    }

    int sniffIndex = findSniffID(packet->forwardID);
    if (sniffIndex == -1)
    {
        // 新监听对象，初始化统计项
        sniffIndex = sniffTableCount;
        sniffTable[sniffIndex].lastSniffTime = HAL_GetTick();
        sniffTable[sniffIndex].sourceID = packet->forwardID;
        sniffTable[sniffIndex].snifferID = nodeID;
        sniffTable[sniffIndex].forwardCount = 0;
        sniffTable[sniffIndex].sourceCount = 0;
        sniffTable[sniffIndex].ackCount = 0;
        sniffTable[sniffIndex].routeReqCount = 0;
        sniffTable[sniffIndex].routeRepCount = 0;
        sniffTable[sniffIndex].lastRSSI = RSSI;
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
 * @brief 查找监听表中是否已有该转发节点记录。
 */
static int findSniffID(uint8_t forwardID)
{
    for (int i = 0; i < sniffTableCount; i++)
    {
        if (sniffTable[i].sourceID == forwardID)
        {
            return i;
        }
    }
    return -1;
}

/**
 * @brief 透明传输对 0x00 不友好，统一转为 0xFF。
 */
static void sanitizeData(uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        if (data[i] == 0x00)
        {
            data[i] = 0xFF;
        }
    }
}

/**
 * @brief 接收后将 0xFF 还原为 0x00。
 */
static void restoreData(uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        if (data[i] == 0xFF)
        {
            data[i] = 0x00;
        }
    }
}

static void writeAsciiData(char *data, size_t len, const char *str)
{
    size_t slen = strlen(str);
    if (slen > len)
    {
        slen = len;
    }
    memset(data, 0xFF, len);
    memcpy(data, str, slen);
}

static uint8_t cmdFromString(const char *cmd)
{
    if (cmd == NULL)
    {
        return 0;
    }
    if (strcmp(cmd, "MODE") == 0)
    {
        return CMD_MODE;
    }
    if (strcmp(cmd, "ROUND") == 0)
    {
        return CMD_ROUND;
    }
    if (strcmp(cmd, "ONOFF") == 0)
    {
        return CMD_ONOFF;
    }
    if (strcmp(cmd, "ROUTE") == 0)
    {
        return CMD_ROUTE;
    }
    if (strcmp(cmd, "DROP") == 0)
    {
        return CMD_DROP;
    }
    return 0;
}

static const char *cmdToString(uint8_t cmd)
{
    switch (cmd)
    {
    case CMD_MODE:
        return "MODE";
    case CMD_ROUND:
        return "ROUND";
    case CMD_ONOFF:
        return "ONOFF";
    case CMD_ROUTE:
        return "ROUTE";
    case CMD_DROP:
        return "DROP";
    default:
        return "UNK";
    }
}

static int parseControlString(const char *str, uint8_t *seq, uint8_t *cmd, int32_t *p1, int32_t *p2)
{
    char tmp[CTRL_STR_MAX + 1];
    char *tok = NULL;
    char *endptr = NULL;

    if (str == NULL || seq == NULL || cmd == NULL || p1 == NULL || p2 == NULL)
    {
        return 0;
    }

    strncpy(tmp, str, CTRL_STR_MAX);
    tmp[CTRL_STR_MAX] = '\0';

    tok = strtok(tmp, ",");
    if (tok == NULL || tok[0] != 'C')
    {
        return 0;
    }

    tok = strtok(NULL, ",");
    if (tok == NULL)
    {
        return 0;
    }
    *seq = (uint8_t)strtoul(tok, &endptr, 10);

    tok = strtok(NULL, ",");
    if (tok == NULL)
    {
        return 0;
    }
    *cmd = cmdFromString(tok);
    if (*cmd == 0)
    {
        return 0;
    }

    tok = strtok(NULL, ",");
    if (tok == NULL)
    {
        return 0;
    }
    *p1 = (int32_t)strtol(tok, &endptr, 10);

    tok = strtok(NULL, ",");
    if (tok == NULL)
    {
        return 0;
    }
    *p2 = (int32_t)strtol(tok, &endptr, 10);

    return 1;
}

static uint8_t applyControlCommand(uint8_t cmd, int32_t p1, int32_t p2)
{
    switch (cmd)
    {
    case CMD_MODE:
        if (p1 == 0)
        {
            isMalicious = 0;
            maliciousType = 0;
        }
        else
        {
            isMalicious = 1;
            if (p2 >= 1 && p2 <= 3)
            {
                maliciousType = (uint8_t)p2;
            }
            else
            {
                maliciousType = 1;
            }
        }
        return 1;
    case CMD_ROUND:
        if (p1 < 1000)
        {
            p1 = 1000;
        }
        if (p1 > 600000)
        {
            p1 = 600000;
        }
        roundTime = (uint32_t)p1;
        return 1;
    case CMD_ONOFF:
        onoffEnabled = (p1 != 0);
        if (p2 == 0 || p2 == 1)
        {
            onoffOn = (uint8_t)p2;
        }
        return 1;
    case CMD_ROUTE:
        if (nodeID == NODE_ID_UNASSIGNED)
        {
            return 0;
        }
        routingTableCount = 0;
        if (routingTable != NULL && routingTableSize > 0)
        {
            routingTable[0].destID = nodeID;
            routingTable[0].nextHopID = nodeID;
            routingTable[0].macHigh = MacH;
            routingTable[0].macLow = MacL;
            routingTable[0].lastSeen = HAL_GetTick();
            routingTable[0].hop = 0;
            routingTable[0].rssi = 0;
            routingTable[0].noise = 0;
            routingTableCount = 1;
        }
        sendRouteRequest(targetID);
        previousRouteReq = HAL_GetTick();
        sendRoutRequest = 1;
        getRoutReplay = 0;
        return 1;
    case CMD_DROP:
        if (p1 <= 0)
        {
            dropPolicy = 0;
            dropRate = 0;
        }
        else if (p1 == 1)
        {
            dropPolicy = 1;
            dropRate = 0;
        }
        else if (p1 == 2)
        {
            dropPolicy = 2;
            if (p2 < 0)
            {
                p2 = 0;
            }
            if (p2 > 100)
            {
                p2 = 100;
            }
            dropRate = (uint8_t)p2;
        }
        else
        {
            return 0;
        }
        return 1;
    default:
        return 0;
    }
}

/**
 * @brief 伪造监听数据（恶意节点行为）。
 */
static void fabricateSniffData(uint8_t *data)
{
    data[10] = 0xFF;
    data[11] = 0xFF;
    data[12] = 0xFF;
    data[13] = 0xFF;
    data[14] = 0xFF;
    data[22] = 0xFF;
    data[23] = 0xFF;
    data[24] = 0xFF;
    data[25] = 0xFF;
    data[26] = 0xFF;
}

/**
 * @brief 设置随机种子，用于恶意行为概率判断。
 */
static void seedRandom(void)
{
    srand((unsigned int)(deviceUID ^ HAL_GetTick()));
}

/**
 * @brief 获取设备唯一 ID（基于芯片 UID 或系统时钟）。
 */
static uint32_t getDeviceUID(void)
{
#if defined(HAL_GetUIDw0)
    return HAL_GetUIDw0() ^ HAL_GetUIDw1() ^ HAL_GetUIDw2();
#else
    return HAL_GetTick();
#endif
}

/**
 * @brief 初始化 UID 及其字符串表示。
 */
static void initDeviceUID(void)
{
    deviceUID = getDeviceUID();
    snprintf(deviceUIDStr, sizeof(deviceUIDStr), "%08lX", (unsigned long)deviceUID);
}

/**
 * @brief 按概率决定是否成为恶意节点并选择攻击类型。
 */
static void decideMalicious(void)
{
    if (NODE_ROLE_SINK)
    {
        return;
    }
    uint8_t roll = (uint8_t)(rand() % 100);
    if (roll < MALICIOUS_PROB)
    {
        isMalicious = 1;
        maliciousType = (uint8_t)(1 + (rand() % 3));
    }
    else
    {
        isMalicious = 0;
        maliciousType = 0;
    }
}

/**
 * @brief on-off 攻击节律控制。
 */
static void updateOnOff(void)
{
    if (!onoffEnabled)
    {
        return;
    }
    onoffCount++;
    if (onoffCount % 5 == 4)
    {
        onoffOn = !onoffOn;
    }
}

/**
 * @brief 路由请求去重，防止广播风暴。
 */
static int isDuplicateRouteReq(uint8_t sourceID, uint8_t reqID)
{
    uint32_t now = HAL_GetTick();
    for (int i = 0; i < ROUTE_REQ_CACHE_SIZE; i++)
    {
        if (routeReqCache[i].sourceID == sourceID && routeReqCache[i].requestID == reqID)
        {
            if (now - routeReqCache[i].lastSeen < ROUTE_REQ_TIMEOUT)
            {
                routeReqCache[i].lastSeen = now;
                return 1;
            }
        }
    }

    for (int i = 0; i < ROUTE_REQ_CACHE_SIZE; i++)
    {
        if (routeReqCache[i].sourceID == NODE_ID_UNASSIGNED)
        {
            routeReqCache[i].sourceID = sourceID;
            routeReqCache[i].requestID = reqID;
            routeReqCache[i].lastSeen = now;
            return 0;
        }
    }

    routeReqCache[0].sourceID = sourceID;
    routeReqCache[0].requestID = reqID;
    routeReqCache[0].lastSeen = now;
    return 0;
}

/**
 * @brief 初始化路由请求去重缓存。
 */
static void initRouteReqCache(void)
{
    for (int i = 0; i < ROUTE_REQ_CACHE_SIZE; i++)
    {
        routeReqCache[i].sourceID = NODE_ID_UNASSIGNED;
        routeReqCache[i].requestID = 0;
        routeReqCache[i].lastSeen = 0;
    }
}

static int isDuplicateControl(uint8_t sourceID, uint8_t seq, uint8_t cmd)
{
    uint32_t now = HAL_GetTick();
    for (int i = 0; i < CONTROL_CACHE_SIZE; i++)
    {
        if (controlCache[i].sourceID == sourceID &&
            controlCache[i].seq == seq &&
            controlCache[i].cmd == cmd)
        {
            if (now - controlCache[i].lastSeen < CONTROL_CACHE_TIMEOUT)
            {
                controlCache[i].lastSeen = now;
                return 1;
            }
        }
    }

    for (int i = 0; i < CONTROL_CACHE_SIZE; i++)
    {
        if (controlCache[i].sourceID == NODE_ID_UNASSIGNED)
        {
            controlCache[i].sourceID = sourceID;
            controlCache[i].seq = seq;
            controlCache[i].cmd = cmd;
            controlCache[i].lastSeen = now;
            return 0;
        }
    }

    controlCache[0].sourceID = sourceID;
    controlCache[0].seq = seq;
    controlCache[0].cmd = cmd;
    controlCache[0].lastSeen = now;
    return 0;
}

static void initControlCache(void)
{
    for (int i = 0; i < CONTROL_CACHE_SIZE; i++)
    {
        controlCache[i].sourceID = NODE_ID_UNASSIGNED;
        controlCache[i].seq = 0;
        controlCache[i].cmd = 0;
        controlCache[i].lastSeen = 0;
    }
}

/**
 * @brief 在 OLED 上显示当前节点 ID。
 */
static void updateNodeDisplay(void)
{
    sprintf(nodeIDStr, "%d", nodeID);
    OLED_ShowString(100, 0, (unsigned char *)nodeIDStr);
}

/**
 * @brief 采集传感器数据并发送到汇聚节点。
 * 同时携带监听表统计数据。
 */
static void sendSensorData(void)
{
    if (nodeID == NODE_ID_UNASSIGNED)
    {
        return;
    }

#if NODE_ENABLE_SENSOR
    if (DHT11_READ_DATA() == 1)
    {
        DataPacket datapacket;
        memset(&datapacket, 0, sizeof(datapacket));
        datapacket.data[0] = Dht11data[2];
        datapacket.data[1] = Dht11data[3];
        datapacket.data[2] = Dht11data[0];
        datapacket.data[3] = Dht11data[1];

        // 打包监听表数据（轮询两条记录，保持与原项目格式一致）
        if (sniffTableCount > 0)
        {
            memcpy(&datapacket.data[4], &sniffTable[sniffTableSendID % sniffTableCount], sizeof(SnifferTable));
            sniffTableSendID++;
            if (sniffTableCount > 1)
            {
                memcpy(&datapacket.data[4 + sizeof(SnifferTable)], &sniffTable[sniffTableSendID % sniffTableCount], sizeof(SnifferTable));
                sniffTableSendID++;
            }
        }

        // 查找路由并发送
        int routeIndex = findRoute(targetID);
        if (routeIndex != -1)
        {
            datapacket.destMacH = routingTable[routeIndex].macHigh;
            datapacket.destMacL = routingTable[routeIndex].macLow;
            datapacket.destchanID = channelID;
            datapacket.sourceMacH = MacH;
            datapacket.sourceMacL = MacL;
            datapacket.sourceID = nodeID;
            datapacket.forwardID = nodeID;
            datapacket.forwardtoID = routingTable[routeIndex].nextHopID;
            datapacket.destID = targetID;
            datapacket.ID = packetID++;
            datapacket.protocol = DATA_PACKET;
            sanitizeData((uint8_t *)datapacket.data, sizeof(datapacket.data));

            memcpy(packetBUF, &datapacket, sizeof(datapacket));
            USART2_printf("%s\n", packetBUF);
            previousNotGetACK++;
        }
        else
        {
            // 未找到路由则发起路由请求
            sendRouteRequest(targetID);
            previousRouteReq = HAL_GetTick();
            sendRoutRequest = 1;
            getRoutReplay = 0;
        }

        // 连续未 ACK 则删除路由条目，触发重新发现
        if (previousNotGetACK >= ACK_MISS_THRESHOLD && routeIndex != -1)
        {
            deleteRoutingEntry((uint8_t)routeIndex);
            previousNotGetACK = 0;
        }
    }
#else
    (void)roundTime;
#endif
}

#if NODE_ENABLE_WIFI
/**
 * @brief 连接 WiFi 与 TCP 服务器（仅簇头使用）。
 */
static void connectServer(void)
{
    uint8_t tryCount = 0;
    if (linkMode == LINK_MODE_SERIAL)
    {
        return;
    }

    res = 1;
    for (tryCount = 0; tryCount < WIFI_CONNECT_TRY_MAX && res; tryCount++)
    {
        res = WIFI_Dect((uint8_t *)SSID, (uint8_t *)Password);
        HAL_Delay(200);
    }
    if (res)
    {
        linkMode = LINK_MODE_SERIAL;
        return;
    }

    HAL_GPIO_WritePin(LED1_GPIO_Port, LED1_Pin, GPIO_PIN_RESET);

    res = 1;
    for (tryCount = 0; tryCount < SERVER_CONNECT_TRY_MAX && servernotok; tryCount++)
    {
        res = ESP8266_CONNECT_SERVER((uint8_t *)ServerIP, (uint8_t *)Port);
        HAL_Delay(1000);
    }

    if (!servernotok)
    {
        linkMode = LINK_MODE_WIFI;
    }
    else
    {
        linkMode = LINK_MODE_SERIAL;
    }
}
#endif

#if NODE_ROLE_SINK
/**
 * @brief 为新节点分配 ID，基于 UID 去重。
 */
static uint8_t assignNodeID(uint32_t uid)
{
    for (int i = 0; i < nodeRegistryCount; i++)
    {
        if (nodeRegistry[i].uid == uid)
        {
            nodeRegistry[i].lastSeen = HAL_GetTick();
            return nodeRegistry[i].nodeID;
        }
    }

    if (nodeRegistryCount >= MAX_NODES || nextNodeID == NODE_ID_UNASSIGNED)
    {
        return NODE_ID_UNASSIGNED;
    }

    nodeRegistry[nodeRegistryCount].uid = uid;
    nodeRegistry[nodeRegistryCount].nodeID = nextNodeID;
    nodeRegistry[nodeRegistryCount].lastSeen = HAL_GetTick();
    nodeRegistryCount++;
    nextNodeID++;
    return nodeRegistry[nodeRegistryCount - 1].nodeID;
}

static void handleTcpCommandBuffer(const uint8_t *buf)
{
    char tmp[USART_REC_LEN + 1];
    char *line = NULL;
    char *end = NULL;
    char *tok = NULL;
    uint32_t dest = 0;
    uint8_t seq = 0;
    uint8_t cmd = 0;
    int32_t p1 = 0;
    int32_t p2 = 0;
    uint8_t status = 0;
    size_t len = 0;

    while (len < USART_REC_LEN && buf[len] != 0)
    {
        len++;
    }
    memcpy(tmp, buf, len);
    tmp[len] = '\0';

    line = strstr(tmp, "CTRL,");
    if (line == NULL)
    {
        return;
    }
    end = strchr(line, '\n');
    if (end)
    {
        *end = '\0';
    }
    end = strchr(line, '\r');
    if (end)
    {
        *end = '\0';
    }

    tok = strtok(line, ",");
    if (tok == NULL || strcmp(tok, "CTRL") != 0)
    {
        return;
    }
    tok = strtok(NULL, ",");
    if (tok == NULL)
    {
        return;
    }
    dest = strtoul(tok, NULL, 10);
    if (dest > 255)
    {
        dest = 255;
    }

    tok = strtok(NULL, ",");
    if (tok == NULL)
    {
        return;
    }
    cmd = cmdFromString(tok);
    if (cmd == 0)
    {
        return;
    }

    tok = strtok(NULL, ",");
    if (tok == NULL)
    {
        return;
    }
    p1 = (int32_t)strtol(tok, NULL, 10);

    tok = strtok(NULL, ",");
    if (tok == NULL)
    {
        return;
    }
    p2 = (int32_t)strtol(tok, NULL, 10);

    tok = strtok(NULL, ",");
    if (tok == NULL)
    {
        return;
    }
    seq = (uint8_t)strtoul(tok, NULL, 10);

    sendControlPacket((uint8_t)dest, seq, cmd, p1, p2);

    if (dest == nodeID || dest == 0xFF)
    {
        status = applyControlCommand(cmd, p1, p2);
        sendControlAckToServer(seq, cmd, status);
    }
}
#endif

/**
 * @brief 主函数入口。
 * 初始化硬件、协议、显示与模块后进入主循环。
 */
int main(void)
{
    int i;

    //========================== MCU 初始化 ==========================//
    HAL_Init();
    SystemClock_Config();
    MX_GPIO_Init();
    MX_USART1_UART_Init();
    MX_USART2_UART_Init();
    USART_Interupt_Enable();

    // 初始化 UID / 随机种子 / 路由与去重缓存
    initDeviceUID();
    seedRandom();

    routingTableSize = 2;
    routingTable = (RoutingEntry *)malloc(routingTableSize * sizeof(RoutingEntry));
    initRouteReqCache();
    initControlCache();

    //========================== OLED 与 LoRa 初始化 ==========================//
    printf("LORA Board LED OK\r\n");
    CS_OLED_Init();
    OLED_Clear();
    OLED_ShowString(16, 0, "WWSN NODE");
    updateNodeDisplay();
    cstxInitialize();
    configureModule();

    // 读写寄存器模式下打印模块参数
    if (HAL_GPIO_ReadPin(M1_GPIO_Port, M1_Pin) == 1)
    {
        CS_Reg_Send_Data(cscxReg, sizeof(cscxReg));
        HAL_Delay(300);
        cstx_reg_Receive_Data(csrevReg, &key);

        OLED_ShowString(0, 2, "Addr:");
        for (i = 3; i < 5; i++)
        {
            sprintf((char *)disOLED, "%02X", csrevReg[i]);
            OLED_ShowString(i * 16 - 4, 2, disOLED);
        }

        OLED_ShowString(82, 2, "Ch:");
        sprintf((char *)disOLED, "%02X", csrevReg[8]);
        OLED_ShowString(104, 2, disOLED);
    }

    // 切回透明传输模式
    HAL_GPIO_WritePin(M1_GPIO_Port, M1_Pin, GPIO_PIN_RESET);
    HAL_Delay(1000);
    memset(USART2_RX_BUF, 0, USART_REC_LEN);
    USART2_RX_STA = 0;
    memset(USART_RX_BUF, 0, USART_REC_LEN);
    USART_RX_STA = 0;

    // 若本节点已有 ID，则先添加自路由
    if (nodeID != NODE_ID_UNASSIGNED)
    {
        addRoutingEntry(nodeID, nodeID, MacH, MacL, 0, 0, 0);
    }

    DataPacket receivedPacket;

    while (1)
    {
        uint32_t currentMillis = HAL_GetTick();

        //====================== 动态入网 ======================//
        if (!NODE_ROLE_SINK && nodeID == NODE_ID_UNASSIGNED)
        {
            if (currentMillis - previousJoinReq > JOIN_REQUEST_INTERVAL || previousJoinReq == 0)
            {
                previousJoinReq = currentMillis;
                sendJoinRequest();
            }
        }

        if (nodeID != NODE_ID_UNASSIGNED)
        {
            //================== 周期性采集与发送 ==================//
            if (currentMillis - previousMillisA0 >= roundTime || previousMillisA0 == 0)
            {
                previousMillisA0 = currentMillis;
                updateOnOff();
                sendSensorData();
            }

            //================== 路由表定期清理 ==================//
            if (currentMillis - lastRoutePrune >= ROUTE_PRUNE_INTERVAL)
            {
                lastRoutePrune = currentMillis;
                pruneRoutingTable();
            }

            if (currentMillis - previousStatusReport >= STATUS_REPORT_INTERVAL || previousStatusReport == 0)
            {
                previousStatusReport = currentMillis;
                sendStatusPacket();
            }

            if (pendingCtrlAckValid)
            {
                int routeIndex = findRoute(targetID);
                if (routeIndex != -1 || nodeID == targetID)
                {
                    uint8_t seq = pendingCtrlAckSeq;
                    uint8_t cmd = pendingCtrlAckCmd;
                    uint8_t status = pendingCtrlAckStatus;
                    pendingCtrlAckValid = 0;
                    sendControlAckPacket(seq, cmd, status);
                }
            }

            //================== 路由请求重试 ==================//
            if (sendRoutRequest == 1 && getRoutReplay == 0)
            {
                if (currentMillis - previousRouteReq > ROUTE_REQ_RETRY)
                {
                    sendRouteRequest(targetID);
                    previousRouteReq = currentMillis;
                }
            }
        }

        //====================== 接收处理 ======================//
        if (USART2_RX_STA == REC_OK)
        {
            receivedPacket.destMacH = 0xFF;
            receivedPacket.destMacL = 0xFF;
            receivedPacket.destchanID = channelID;
            receivedPacket.sourceMacH = USART2_RX_BUF[0];
            receivedPacket.sourceMacL = USART2_RX_BUF[1];
            receivedPacket.sourceID = USART2_RX_BUF[2];
            receivedPacket.forwardID = USART2_RX_BUF[3];
            receivedPacket.forwardtoID = USART2_RX_BUF[4];
            receivedPacket.destID = USART2_RX_BUF[5];
            receivedPacket.protocol = USART2_RX_BUF[6];
            receivedPacket.ID = USART2_RX_BUF[7];
            memcpy(receivedPacket.data, &USART2_RX_BUF[8], sizeof(receivedPacket.data));
            restoreData((uint8_t *)receivedPacket.data, sizeof(receivedPacket.data));

            // 从尾部解析 RSSI（沿用原项目做法）
            for (int idx = 65 - 1; idx >= 0; idx--)
            {
                if (USART2_RX_BUF[idx] != 0)
                {
                    RSSI = USART2_RX_BUF[idx];
                    break;
                }
            }

            // 若转发目标是自己/广播/自己为终点，则处理数据包
            if (receivedPacket.forwardtoID == nodeID || receivedPacket.forwardtoID == 0xFF || receivedPacket.destID == nodeID)
            {
                handleReceivedPacket(&receivedPacket);
            }
            // 无论是否处理，均进行监听统计
            sniff(&receivedPacket);

            memset(USART2_RX_BUF, 0, USART_REC_LEN);
            USART2_RX_STA = 0;
        }

        //====================== TCP 命令/串口透传 ======================//
#if NODE_ROLE_SINK
        if (USART_RX_STA == REC_OK)
        {
            handleTcpCommandBuffer(USART_RX_BUF);
            memset(USART_RX_BUF, 0, USART_REC_LEN);
            USART_RX_STA = 0;
        }
#else
        if (USART_RX_STA == REC_OK)
        {
            USART2_printf("%s\n", USART_RX_BUF);
            memset(USART_RX_BUF, 0, USART_REC_LEN);
            USART_RX_STA = 0;
        }
#endif
    }
}

/**
 * @brief 系统时钟配置（保持与原工程一致）。
 */
void SystemClock_Config(void)
{
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
    RCC_PeriphCLKInitTypeDef PeriphClkInit = {0};

    HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1);
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

    RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1;
    RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;

    if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
    {
        Error_Handler();
    }

    PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_USART1;
    PeriphClkInit.Usart1ClockSelection = RCC_USART1CLKSOURCE_PCLK1;
    if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit) != HAL_OK)
    {
        Error_Handler();
    }
}

/**
 * @brief 错误处理函数。
 */
void Error_Handler(void)
{
    __disable_irq();
    while (1)
    {
    }
}

#ifdef USE_FULL_ASSERT
void assert_failed(uint8_t *file, uint32_t line)
{
    (void)file;
    (void)line;
}
#endif
