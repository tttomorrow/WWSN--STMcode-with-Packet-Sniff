/* 发送模块：入网报文、路由报文、业务数据与控制应答发送。 */

#include "wwsn_shared.h"

void sendDataPacket(DataPacket *packet)
{
    /* 通过串口透传发送完整 DataPacket。 */
    uint16_t i;
    memcpy(packetBUF, packet, sizeof(DataPacket));
    for (i = 0; i < sizeof(DataPacket); i++)
    {
        while ((USART2->ISR & 0x40) == 0)
            ;
        USART2->TDR = packetBUF[i];
    }
    while ((USART2->ISR & 0x40) == 0)
        ;
}

void sendJoinRequest(void)
{
    /* 成员节点未分配 ID 时，周期发送入网请求。 */
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
#if JOIN_DEBUG_SERIAL
    printf("JOIN_REQ uid=%s id=%u pkt=%u\r\n", deviceUIDStr, (unsigned int)nodeID, (unsigned int)packet.ID);
#endif
    sendDataPacket(&packet);
}

#if NODE_ROLE_SINK
void sendJoinAssign(uint32_t uid, uint8_t assignedID)
{
    /* Sink 将 UID 与分配的网络 ID 下发给成员节点。 */
    DataPacket packet;
    char uidStr[9];
    char idStr[3];
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
    snprintf(uidStr, sizeof(uidStr), "%08lX", (unsigned long)uid);
    snprintf(idStr, sizeof(idStr), "%02X", assignedID);
    memcpy(packet.data, uidStr, 8);
    memcpy(&packet.data[8], idStr, 2);
    packet.ID = packetID++;
    /* Sink 无串口调试条件下也输出到 TCP 链路，便于服务器侧定位入网流程。 */
    printf("JOIN_ASSIGN_TX uid=%s assigned=%u pkt=%u\r\n",
           uidStr,
           (unsigned int)assignedID,
           (unsigned int)packet.ID);
    sinkJoinAssignTxCount++;
    updateSinkJoinDebugDisplay();
    sendDataPacket(&packet);
}
#endif

void sendRouteRequest(uint8_t destID)
{
    /* 广播路由请求，寻找到目的节点的路径。 */
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

void sendRouteReply(uint8_t requestorID, uint8_t replySourceID, uint8_t nextHopID)
{
    /* 按反向路径返回路由应答。 */
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

void sendAckPacket(uint8_t destID, uint8_t macH, uint8_t macL)
{
    /* 对收到的业务包发送链路层 ACK。 */
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

#if NODE_ROLE_SINK
void sendControlPacket(uint8_t destID, uint8_t seq, uint8_t cmd, int32_t p1, int32_t p2)
{
    /* Sink 下发控制命令，支持单播与广播。 */
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
#endif

void sendControlAckPacket(uint8_t seq, uint8_t cmd, uint8_t status)
{
    /* 节点执行控制命令后回传 ACK。 */
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

#if NODE_ROLE_SINK
void sendControlAckToServer(uint8_t seq, uint8_t cmd, uint8_t status)
{
    printf("ACK,A,%u,%s,%u,%u\r\n",
           (unsigned int)seq,
           cmdToString(cmd),
           (unsigned int)status,
           (unsigned int)nodeID);
}
#endif

void sendStatusPacket(void)
{
    /* 周期上报节点状态（轮询周期、开关、恶意模式等）。 */
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



