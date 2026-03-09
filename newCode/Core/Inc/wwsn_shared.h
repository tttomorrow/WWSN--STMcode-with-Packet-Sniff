#ifndef WWSN_SHARED_H
#define WWSN_SHARED_H

#include "main.h"
#include "usart.h"
#include "gpio.h"
#include "oled.h"
#include "wwsn_config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#if NODE_ENABLE_SENSOR
#include "dht11.h"
#endif

#if NODE_ENABLE_WIFI
#include "mqtt.h"
#include "esp8266.h"
#endif

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

#define LINK_MODE_AUTO 0
#define LINK_MODE_WIFI 1
#define LINK_MODE_SERIAL 2
#define WIFI_CONNECT_TRY_MAX 3
#define SERVER_CONNECT_TRY_MAX 3
#define WIFI_RECONNECT_INTERVAL_MS 5000
#define WIFI_ALLOW_SERIAL_FALLBACK 0

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
#define SINK_PACKET_LOG 1

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

extern uint8_t nodeID;
extern uint8_t targetID;
extern uint32_t roundTime;

extern uint8_t maliciousType;
extern uint8_t isMalicious;
extern uint8_t onoffEnabled;
extern uint8_t onoffOn;
extern uint8_t onoffCount;
extern uint8_t dropPolicy;
extern uint8_t dropRate;

extern unsigned char key;
extern unsigned char RSSIkey;
extern unsigned char disOLED[24];
extern char nodeIDStr[8];

extern RoutingEntry *routingTable;
extern int routingTableSize;
extern int routingTableCount;

extern SnifferTable *sniffTable;
extern int sniffTableSize;
extern int sniffTableCount;
extern uint8_t sniffTableSendID;

extern RouteReqCache routeReqCache[ROUTE_REQ_CACHE_SIZE];
extern ControlCache controlCache[CONTROL_CACHE_SIZE];

extern unsigned char packetBUF[sizeof(DataPacket)];

extern uint32_t previousMillisA0;
extern uint32_t previousRouteReq;
extern uint32_t previousJoinReq;
extern uint32_t lastRoutePrune;
extern uint32_t previousStatusReport;
extern uint8_t previousNotGetACK;
extern uint8_t sendRoutRequest;
extern uint8_t getRoutReplay;
extern uint8_t RSSI;
extern uint8_t packetID;
extern uint32_t deviceUID;
extern char deviceUIDStr[9];
extern uint8_t pendingCtrlAckValid;
extern uint8_t pendingCtrlAckSeq;
extern uint8_t pendingCtrlAckCmd;
extern uint8_t pendingCtrlAckStatus;
extern unsigned char servernotok;

#if NODE_ENABLE_WIFI
extern uint8_t res;
extern uint8_t linkMode;
extern uint32_t previousServerReconnect;
#endif

#if NODE_ROLE_SINK
extern NodeRegistry nodeRegistry[MAX_NODES];
extern uint8_t nodeRegistryCount;
extern uint8_t nextNodeID;
extern uint16_t sinkJoinReqRxCount;
extern uint16_t sinkJoinAssignTxCount;
#endif

extern unsigned char cscxReg[10];
extern unsigned char csrevReg[12];

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

void logSinkPacketReadable(const DataPacket *packet, int16_t rssi_dbm);

#endif
