/* 主文件：全局配置、全局状态、主循环调度（路由/入网/收发/控制）。 */


#include "main.h"
#include "usart.h"
#include "gpio.h"
#include "oled.h"
#include "wwsn_config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* -------------------- 角色与功能开关 -------------------- */
/* -------------------- Sink WiFi/TCP 配置 -------------------- */
#if NODE_ENABLE_WIFI
#ifndef WIFI_SERVER_IP
#define WIFI_SERVER_IP "192.168.31.121"
#endif
#ifndef WIFI_SERVER_PORT
#define WIFI_SERVER_PORT "60000"
#endif
#ifndef WIFI_SSID
#define WIFI_SSID "Wireless Weak-link Network"
#endif
#ifndef WIFI_PASSWORD
#define WIFI_PASSWORD "18239778101"
#endif
#endif

/* -------------------- 连接策略参数 -------------------- */
#define LINK_MODE_AUTO 0
#define LINK_MODE_WIFI 1
#define LINK_MODE_SERIAL 2
#define WIFI_CONNECT_TRY_MAX 3
#define SERVER_CONNECT_TRY_MAX 3
#define WIFI_RECONNECT_INTERVAL_MS 5000
#define WIFI_ALLOW_SERIAL_FALLBACK 0

#if NODE_ENABLE_SENSOR
#include "dht11.h"
#endif

#if NODE_ENABLE_WIFI
#include "mqtt.h"
#include "esp8266.h"
#endif

/* -------------------- 协议字段与时序参数 -------------------- */
#define SDATA "ToggleLED\r\n"
#define ROUTE_REQUEST 0x01
#define ROUTE_REPLY 0x02
#define DATA_PACKET 0x03
#define ACK_PACKET 0x04
#define JOIN_REQUEST 0x10
#define JOIN_ASSIGN 0x11
#define CONTROL_PACKET 0x20
#define CONTROL_ACK 0x21
#define STATUS_PACKET 0x22

#define ROUTING_TABLE_SIZE_INITIAL 10
#define SNIFF_TABLE_SIZE_INITIAL 0
#define ROUTE_REQ_CACHE_SIZE 8
#define ROUTE_REQ_TIMEOUT 20000
#define ROUTE_REQ_RETRY 10000
#define ROUTE_MAX_HOPS 8
#define ROUTE_ENTRY_TIMEOUT 180000
#define ROUTE_PRUNE_INTERVAL 15000
#define CONTROL_CACHE_SIZE 8
#define CONTROL_CACHE_TIMEOUT 20000
#define STATUS_REPORT_INTERVAL 30000
#define JOIN_REQUEST_INTERVAL 6000
#define ACK_MISS_THRESHOLD 5

#define NODE_ID_UNASSIGNED 0xFF
#define TARGET_ID 1
#define MAX_NODES 32

#define MALICIOUS_PROB 30
#define MALICIOUS_DROP_RATE 30

#define CMD_MODE 1
#define CMD_ROUND 2
#define CMD_ONOFF 3
#define CMD_ROUTE 4
#define CMD_DROP 5

#define CTRL_STR_MAX 40

#define MacH 0xFF
#define MacL 0xFF
#define channelID 0x09
#define LORA_NETID 0x01
#define LORA_REG0 0x61
#define LORA_REG1 0x20
#define LORA_REG3 0xD0
#define JOIN_DEBUG 1
#define NODE_SERIAL_DEBUG (!NODE_ROLE_SINK)
#define JOIN_DEBUG_SERIAL (JOIN_DEBUG && NODE_SERIAL_DEBUG)

/* -------------------- 数据结构定义 -------------------- */
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
typedef struct
{
    uint32_t uid;
    uint8_t nodeID;
    uint32_t lastSeen;
} NodeRegistry;
#endif

/* -------------------- 模块函数声明 -------------------- */
void SystemClock_Config(void);

void configureModule(void);
uint8_t configureModuleRegisters(void);
int getEnvirRSSI(void);
void addRoutingEntry(uint8_t destID, uint8_t nextHopID, uint8_t macHigh, uint8_t macLow, uint8_t hop, int16_t rssi, int16_t noise);
void deleteRoutingEntry(uint8_t routeIndex);
int findRoute(uint8_t destID);
void pruneRoutingTable(void);
int isBetterRoute(uint8_t newHop, int16_t newRssi, uint8_t oldHop, int16_t oldRssi);

void sendJoinRequest(void);
#if NODE_ROLE_SINK
void sendJoinAssign(uint32_t uid, uint8_t assignedID);
#endif
void sendRouteRequest(uint8_t destID);
void sendRouteReply(uint8_t requestorID, uint8_t replySourceID, uint8_t nextHopID);
void sendAckPacket(uint8_t destID, uint8_t macH, uint8_t macL);
void sendDataPacket(DataPacket *packet);
#if NODE_ROLE_SINK
void sendControlPacket(uint8_t destID, uint8_t seq, uint8_t cmd, int32_t p1, int32_t p2);
#endif
void sendControlAckPacket(uint8_t seq, uint8_t cmd, uint8_t status);
#if NODE_ROLE_SINK
void sendControlAckToServer(uint8_t seq, uint8_t cmd, uint8_t status);
#endif
void sendStatusPacket(void);
void processStatusPacket(DataPacket *packet);

void handleReceivedPacket(DataPacket *packet);
void processJoinRequest(DataPacket *packet);
void processJoinAssign(DataPacket *packet);
void processRouteRequest(DataPacket *packet);
void processRouteReply(DataPacket *packet);
void processDataPacket(DataPacket *packet);
void processAckPacket(DataPacket *packet);
void processControlPacket(DataPacket *packet);
void processControlAckPacket(DataPacket *packet);
void logSinkPacketReadable(const DataPacket *packet, int16_t rssi_dbm);

void sniff(DataPacket *packet);
int findSniffID(uint8_t forwardID);
void sanitizeData(uint8_t *data, size_t len);
void restoreData(uint8_t *data, size_t len);
void writeAsciiData(char *data, size_t len, const char *str);
uint8_t cmdFromString(const char *cmd);
const char *cmdToString(uint8_t cmd);
int parseControlString(const char *str, uint8_t *seq, uint8_t *cmd, int32_t *p1, int32_t *p2);
uint8_t applyControlCommand(uint8_t cmd, int32_t p1, int32_t p2);
void fabricateSniffData(uint8_t *data);
void seedRandom(void);
uint32_t getDeviceUID(void);
void initDeviceUID(void);
void decideMalicious(void);
void updateOnOff(void);
int isDuplicateRouteReq(uint8_t sourceID, uint8_t reqID);
void initRouteReqCache(void);
int isDuplicateControl(uint8_t sourceID, uint8_t seq, uint8_t cmd);
void initControlCache(void);
void updateNodeDisplay(void);
#if NODE_ROLE_SINK
void updateSinkJoinDebugDisplay(void);
#endif
void sendSensorData(void);

#if NODE_ENABLE_WIFI
void connectServer(void);
#endif

#if NODE_ROLE_SINK
uint8_t assignNodeID(uint32_t uid);
void handleTcpCommandBuffer(const uint8_t *buf);
#endif

#if NODE_ROLE_SINK
uint8_t nodeID = TARGET_ID;
#else
uint8_t nodeID = NODE_ID_UNASSIGNED;
#endif

uint8_t targetID = TARGET_ID;
uint32_t roundTime = 20000;

uint8_t maliciousType = 0;
uint8_t isMalicious = 0;
uint8_t onoffEnabled = 1;
uint8_t onoffOn = 1;
uint8_t onoffCount = 0;
uint8_t dropPolicy = 0;
uint8_t dropRate = 0;

unsigned char key = 0;
unsigned char RSSIkey = 0;
unsigned char disOLED[24];
char nodeIDStr[8];

RoutingEntry *routingTable = NULL;
int routingTableSize = ROUTING_TABLE_SIZE_INITIAL;
int routingTableCount = 0;

SnifferTable *sniffTable = NULL;
int sniffTableSize = SNIFF_TABLE_SIZE_INITIAL;
int sniffTableCount = 0;
uint8_t sniffTableSendID = 0;

RouteReqCache routeReqCache[ROUTE_REQ_CACHE_SIZE];
ControlCache controlCache[CONTROL_CACHE_SIZE];

unsigned char packetBUF[sizeof(DataPacket)];

uint32_t previousMillisA0 = 0;
uint32_t previousRouteReq = 0;
uint32_t previousJoinReq = 0;
uint32_t lastRoutePrune = 0;
uint32_t previousStatusReport = 0;
uint8_t previousNotGetACK = 0;
uint8_t sendRoutRequest = 0;
uint8_t getRoutReplay = 0;
uint8_t RSSI = 0;
uint8_t packetID = 1;
uint32_t deviceUID = 0;
char deviceUIDStr[9];
uint8_t pendingCtrlAckValid = 0;
uint8_t pendingCtrlAckSeq = 0;
uint8_t pendingCtrlAckCmd = 0;
uint8_t pendingCtrlAckStatus = 0;
unsigned char servernotok = 1;

#if NODE_ENABLE_WIFI
uint8_t res = 1;
uint8_t linkMode = LINK_MODE_AUTO;
uint32_t previousServerReconnect = 0;
#endif

#if NODE_ROLE_SINK
NodeRegistry nodeRegistry[MAX_NODES];
uint8_t nodeRegistryCount = 0;
uint8_t nextNodeID = 2;
uint16_t sinkJoinReqRxCount = 0;
uint16_t sinkJoinAssignTxCount = 0;
#endif

unsigned char cscxReg[10] = {0xC0, 0x00, 0x07, MacH, MacL, LORA_NETID, LORA_REG0, LORA_REG1, channelID, LORA_REG3};
unsigned char csrevReg[12] = {0xC1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


/* -------------------- 主循环：初始化与周期调度 -------------------- */
int main(void)
{
    int i;

    HAL_Init();
    SystemClock_Config();
    MX_GPIO_Init();
    MX_USART1_UART_Init();
    MX_USART2_UART_Init();
    USART_Interupt_Enable();

    initDeviceUID();
#if NODE_ROLE_SINK
    printf("ROLE=SINK nodeID=%u targetID=%u\r\n", (unsigned int)nodeID, (unsigned int)targetID);
#else
    printf("ROLE=MEMBER nodeID=%u targetID=%u\r\n", (unsigned int)nodeID, (unsigned int)targetID);
#endif
    seedRandom();

    routingTableSize = 2;
    routingTable = (RoutingEntry *)malloc(routingTableSize * sizeof(RoutingEntry));
    initRouteReqCache();
    initControlCache();

    printf("LORA Board LED OK\r\n");
    CS_OLED_Init();
    OLED_Clear();
    OLED_ShowString(16, 0, "WWSN NODE");
    updateNodeDisplay();
#if NODE_ROLE_SINK
    updateSinkJoinDebugDisplay();
#endif
    cstxInitialize();
    configureModule();

    key = configureModuleRegisters();

    OLED_ShowString(0, 2, "Addr:");
    for (i = 3; i < 5; i++)
    {
        sprintf((char *)disOLED, "%02X", (key ? csrevReg[i] : cscxReg[i]));
        OLED_ShowString(i * 16 - 4, 2, disOLED);
    }
    OLED_ShowString(82, 2, "Ch:");
    sprintf((char *)disOLED, "%02X", (key ? csrevReg[8] : cscxReg[8]));
    OLED_ShowString(104, 2, disOLED);
    OLED_ShowString(0, 4, (unsigned char *)(key ? "CFG OK" : "CFG ERR"));

    HAL_GPIO_WritePin(M1_GPIO_Port, M1_Pin, GPIO_PIN_RESET);
    HAL_GPIO_WritePin(M0_GPIO_Port, M0_Pin, GPIO_PIN_RESET);
    HAL_Delay(300);
    memset(USART2_RX_BUF, 0, USART_REC_LEN);
    USART2_RX_STA = 0;
    memset(USART_RX_BUF, 0, USART_REC_LEN);
    USART_RX_STA = 0;

    if (nodeID != NODE_ID_UNASSIGNED)
    {
        addRoutingEntry(nodeID, nodeID, MacH, MacL, 0, 0, 0);
    }

    DataPacket receivedPacket;

    while (1)
    {
        uint32_t currentMillis = HAL_GetTick();

        /* 1) Sink WiFi/TCP 保活重连 */
#if NODE_ENABLE_WIFI && NODE_ROLE_SINK
        if ((servernotok || res) && (!WIFI_ALLOW_SERIAL_FALLBACK || linkMode != LINK_MODE_SERIAL))
        {
            if (previousServerReconnect == 0 || (currentMillis - previousServerReconnect) >= WIFI_RECONNECT_INTERVAL_MS)
            {
                previousServerReconnect = currentMillis;
                connectServer();
            }
        }
#endif
        /* 2) 入网流程：未分配 ID 的成员节点周期发 JOIN 请求 */
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
            /* 3) 业务发送：周期采样并上报 */
            if (currentMillis - previousMillisA0 >= roundTime || previousMillisA0 == 0)
            {
                previousMillisA0 = currentMillis;
                updateOnOff();
                sendSensorData();
            }
            /* 4) 路由维护：定期清理超时项 */
            if (currentMillis - lastRoutePrune >= ROUTE_PRUNE_INTERVAL)
            {
                lastRoutePrune = currentMillis;
                pruneRoutingTable();
            }
            /* 5) 状态上报：定期发送 STAT */
            if (currentMillis - previousStatusReport >= STATUS_REPORT_INTERVAL || previousStatusReport == 0)
            {
                previousStatusReport = currentMillis;
                sendStatusPacket();
            }
            /* 6) 控制应答：路由恢复后补发挂起 ACK */
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
            /* 7) 路由重试：等待应答超时后重发 ROUTE_REQ */
            if (sendRoutRequest == 1 && getRoutReplay == 0)
            {
                if (currentMillis - previousRouteReq > ROUTE_REQ_RETRY)
                {
                    sendRouteRequest(targetID);
                    previousRouteReq = currentMillis;
                }
            }
        }
        /* 8) 无线收包：解析 DataPacket 并进入协议处理 */
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
#if JOIN_DEBUG_SERIAL
            if (receivedPacket.protocol == JOIN_REQUEST || receivedPacket.protocol == JOIN_ASSIGN)
            {
                printf("PKT_RX proto=%u src=%u fwd=%u to=%u dst=%u pkt=%u\r\n",
                       (unsigned int)receivedPacket.protocol,
                       (unsigned int)receivedPacket.sourceID,
                       (unsigned int)receivedPacket.forwardID,
                       (unsigned int)receivedPacket.forwardtoID,
                       (unsigned int)receivedPacket.destID,
                       (unsigned int)receivedPacket.ID);
            }
#endif

            for (int idx = 65 - 1; idx >= 0; idx--)
            {
                if (USART2_RX_BUF[idx] != 0)
                {
                    RSSI = USART2_RX_BUF[idx];
                    break;
                }
            }
#if !NODE_ROLE_SINK
            printf("MEMBER_RX proto=%u src=%u fwd=%u to=%u dst=%u pkt=%u rssi=-%ddBm\r\n",
                   (unsigned int)receivedPacket.protocol,
                   (unsigned int)receivedPacket.sourceID,
                   (unsigned int)receivedPacket.forwardID,
                   (unsigned int)receivedPacket.forwardtoID,
                   (unsigned int)receivedPacket.destID,
                   (unsigned int)receivedPacket.ID,
                   256 - RSSI);
#endif
#if NODE_ROLE_SINK
            logSinkPacketReadable(&receivedPacket, (int16_t)RSSI - 256);
#else
            printf("receivedPacketWithRSSI: -%ddBm\r\n", 256 - RSSI);
#endif

            if (receivedPacket.forwardtoID == nodeID || receivedPacket.forwardtoID == 0xFF || receivedPacket.destID == nodeID ||
                (nodeID == NODE_ID_UNASSIGNED && receivedPacket.protocol == JOIN_ASSIGN))
            {
                handleReceivedPacket(&receivedPacket);
            }
            sniff(&receivedPacket);

            memset(USART2_RX_BUF, 0, USART_REC_LEN);
            USART2_RX_STA = 0;
        }

        /* 9) Sink 处理 TCP 控制命令；成员节点保持串口透传 */
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






