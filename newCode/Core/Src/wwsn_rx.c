/* 接收模块：收包可读化、协议分发、路由/入网/控制报文处理。 */

#include "wwsn_shared.h"


#if NODE_ROLE_SINK
static const char *packetTypeName(uint8_t protocol)
{
    switch (protocol)
    {
    case ROUTE_REQUEST:
        return "ROUTE_REQ";
    case ROUTE_REPLY:
        return "ROUTE_REP";
    case DATA_PACKET:
        return "DATA";
    case ACK_PACKET:
        return "ACK";
    case JOIN_REQUEST:
        return "JOIN_REQ";
    case JOIN_ASSIGN:
        return "JOIN_ASSIGN";
    case CONTROL_PACKET:
        return "CTRL";
    case CONTROL_ACK:
        return "CTRL_ACK";
    case STATUS_PACKET:
        return "STAT";
    default:
        return "UNKNOWN";
    }
}

static void payloadAscii(const char *src, char *dst, size_t dstSize)
{
    size_t i = 0;
    size_t j = 0;
    if (dstSize == 0)
    {
        return;
    }
    while (i < sizeof(((DataPacket *)0)->data) && j + 1 < dstSize)
    {
        uint8_t c = (uint8_t)src[i];
        if (c == 0x00)
        {
            break;
        }
        dst[j++] = (char)(isprint((int)c) ? c : '.');
        i++;
    }
    dst[j] = '\0';
}
#endif

/* Sink 端可读化日志：将原始包字段和关键载荷解码输出。 */
void logSinkPacketReadable(const DataPacket *packet, int16_t rssi_dbm)
{
#if NODE_ROLE_SINK
    char text[48];
    char uid[9];
    char assigned[3];

    payloadAscii(packet->data, text, sizeof(text));
    printf("RX proto=%s(0x%02X) src=%u fwd=%u to=%u dst=%u id=%u rssi=%ddBm\r\n",
           packetTypeName(packet->protocol),
           (unsigned int)packet->protocol,
           (unsigned int)packet->sourceID,
           (unsigned int)packet->forwardID,
           (unsigned int)packet->forwardtoID,
           (unsigned int)packet->destID,
           (unsigned int)packet->ID,
           (int)rssi_dbm);

    switch (packet->protocol)
    {
    case JOIN_REQUEST:
        memcpy(uid, packet->data, 8);
        uid[8] = '\0';
        printf("RX JOIN_REQ uid=%s\r\n", uid);
        break;
    case JOIN_ASSIGN:
        memcpy(uid, packet->data, 8);
        uid[8] = '\0';
        assigned[0] = packet->data[8];
        assigned[1] = packet->data[9];
        assigned[2] = '\0';
        printf("RX JOIN_ASSIGN uid=%s assigned=%s\r\n", uid, assigned);
        break;
    case DATA_PACKET:
        printf("RX DATA temp=%d.%d hum=%d.%d\r\n",
               (int)(uint8_t)packet->data[0],
               (int)(uint8_t)packet->data[1],
               (int)(uint8_t)packet->data[2],
               (int)(uint8_t)packet->data[3]);
        break;
    case CONTROL_PACKET:
        printf("RX CTRL %s\r\n", text);
        break;
    case CONTROL_ACK:
        printf("RX CTRL_ACK %s\r\n", text);
        break;
    case STATUS_PACKET:
        printf("RX STAT %s\r\n", text);
        break;
    default:
        if (text[0] != '\0')
        {
            printf("RX PAYLOAD %s\r\n", text);
        }
        break;
    }
#else
    (void)packet;
    (void)rssi_dbm;
#endif
}


void handleReceivedPacket(DataPacket *packet)
{
    /* 按协议类型分发到具体处理函数。 */
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

void processJoinRequest(DataPacket *packet)
{
    /* Sink 处理入网请求：按 UID 分配或复用节点 ID。 */
#if NODE_ROLE_SINK
    char uidStr[9];
    uint32_t uid = 0;
    memcpy(uidStr, packet->data, 8);
    uidStr[8] = '\0';
    uid = (uint32_t)strtoul(uidStr, NULL, 16);
#if JOIN_DEBUG_SERIAL
    printf("JOIN_REQ_RX uid=%s from=%u pkt=%u\r\n", uidStr, (unsigned int)packet->sourceID, (unsigned int)packet->ID);
#endif
    sinkJoinReqRxCount++;
    updateSinkJoinDebugDisplay();
    if (uid == 0)
    {
        printf("JOIN_ASSIGN_FAIL uid=0 pkt=%u\r\n", (unsigned int)packet->ID);
        return;
    }
    uint8_t assignedID = assignNodeID(uid);
    if (assignedID != NODE_ID_UNASSIGNED)
    {
        sendJoinAssign(uid, assignedID);
    }
    else
    {
        printf("JOIN_ASSIGN_FAIL uid=%08lX reason=NO_ID\r\n", (unsigned long)uid);
    }
#else
    (void)packet;
#endif
}

void processJoinAssign(DataPacket *packet)
{
    /* 成员节点处理入网分配：匹配 UID 后写入 nodeID。 */
    if (NODE_ROLE_SINK || nodeID != NODE_ID_UNASSIGNED)
    {
        return;
    }
    char uidStr[9];
    char idStr[3];
    uint8_t assignedID = NODE_ID_UNASSIGNED;
    memcpy(uidStr, packet->data, 8);
    uidStr[8] = '\0';
#if JOIN_DEBUG_SERIAL
    printf("JOIN_ASSIGN_RX uid=%s self=%s pkt=%u\r\n", uidStr, deviceUIDStr, (unsigned int)packet->ID);
    printf("JOIN_ASSIGN_ID_RAW %02X %02X\r\n", (unsigned int)(uint8_t)packet->data[8], (unsigned int)(uint8_t)packet->data[9]);
#endif
    if (strncmp(uidStr, deviceUIDStr, 8) != 0)
    {
#if JOIN_DEBUG_SERIAL
        printf("JOIN_ASSIGN_SKIP uid mismatch\r\n");
#endif
        return;
    }
    memcpy(idStr, &packet->data[8], 2);
    idStr[2] = '\0';
    assignedID = (uint8_t)strtoul(idStr, NULL, 16);
    if (assignedID == NODE_ID_UNASSIGNED)
    {
#if JOIN_DEBUG_SERIAL
        printf("JOIN_ASSIGN_SKIP invalid id\r\n");
#endif
        return;
    }
    nodeID = assignedID;
#if JOIN_DEBUG_SERIAL
    printf("JOIN_OK nodeID=%u\r\n", (unsigned int)nodeID);
#endif
    addRoutingEntry(nodeID, nodeID, MacH, MacL, 0, 0, 0);
    updateNodeDisplay();
    seedRandom();
    decideMalicious();
    sendRouteRequest(targetID);
    previousRouteReq = HAL_GetTick();
    sendRoutRequest = 1;
    getRoutReplay = 0;
}

void processRouteRequest(DataPacket *packet)
{
    /* 路由请求处理：去重、学习反向路由、命中则应答。 */
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

    if (packet->sourceID != nodeID)
    {
        addRoutingEntry(packet->sourceID, packet->forwardID, packet->sourceMacH, packet->sourceMacL,
                        hopToSource, (int16_t)RSSI - 256, 0);
    }

    if (nodeID == packet->destID)
    {
        sendRouteReply(packet->sourceID, packet->destID, packet->forwardID);
        return;
    }

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

void processRouteReply(DataPacket *packet)
{
    /* 路由应答处理：更新路由并继续沿路径回传。 */
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

    addRoutingEntry(packet->sourceID, packet->forwardID, packet->sourceMacH, packet->sourceMacL,
                    hopToSource, (int16_t)RSSI - 256, 0);

    if (packet->destID == nodeID)
    {
        getRoutReplay = 1;
        sendRoutRequest = 0;
        return;
    }

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

void processDataPacket(DataPacket *packet)
{
    /* 业务数据处理：终点消费数据，中继进行转发。 */
    if (!NODE_ROLE_SINK && nodeID == NODE_ID_UNASSIGNED)
    {
        return;
    }

#if !NODE_ROLE_SINK
    printf("MEMBER_DATA_RX src=%u fwd=%u to=%u dst=%u pkt=%u t=%u.%u h=%u.%u\r\n",
           (unsigned int)packet->sourceID,
           (unsigned int)packet->forwardID,
           (unsigned int)packet->forwardtoID,
           (unsigned int)packet->destID,
           (unsigned int)packet->ID,
           (unsigned int)(uint8_t)packet->data[0],
           (unsigned int)(uint8_t)packet->data[1],
           (unsigned int)(uint8_t)packet->data[2],
           (unsigned int)(uint8_t)packet->data[3]);
#endif

    if (packet->destID == nodeID)
    {
#if !NODE_ROLE_SINK
        printf("MEMBER_DATA_LOCAL pkt=%u from=%u\r\n",
               (unsigned int)packet->ID,
               (unsigned int)packet->sourceID);
#endif
        memset(disOLED, 0, sizeof(disOLED));
        sprintf((char *)disOLED, "T:%d.%dC H:%d.%dR", packet->data[0], packet->data[1], packet->data[2], packet->data[3]);
        OLED_ShowString(0, 6, disOLED);
        sendAckPacket(packet->forwardID, packet->sourceMacH, packet->sourceMacL);
        getEnvirRSSI();
        printf("%02X %02X %02X %02X %02X %02X %02X %02X ",
               (unsigned int)packet->sourceMacH,
               (unsigned int)packet->sourceMacL,
               (unsigned int)packet->sourceID,
               (unsigned int)packet->forwardID,
               (unsigned int)packet->forwardtoID,
               (unsigned int)packet->destID,
               (unsigned int)packet->protocol,
               (unsigned int)packet->ID);
        for (int i = 0; i < (int)sizeof(packet->data); i++)
        {
            printf("%02X ", (unsigned int)(uint8_t)packet->data[i]);
        }
        printf("\r\n");

#if NODE_ENABLE_WIFI
        if (!servernotok && linkMode == LINK_MODE_WIFI)
        {
            OLED_ShowString(0, 2, "Send SERVER OK ");
        }
#endif
        return;
    }

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

    int routeIndex = findRoute(targetID);
    if (routeIndex != -1)
    {
#if !NODE_ROLE_SINK
        printf("MEMBER_DATA_FWD pkt=%u nextHop=%u target=%u\r\n",
               (unsigned int)packet->ID,
               (unsigned int)routingTable[routeIndex].nextHopID,
               (unsigned int)targetID);
#endif
        packet->destMacH = 0xFF;
        packet->destMacL = 0xFF;
        packet->destchanID = channelID;
        packet->sourceMacH = MacH;
        packet->sourceMacL = MacL;
        packet->forwardID = nodeID;
        packet->forwardtoID = routingTable[routeIndex].nextHopID;

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
#if !NODE_ROLE_SINK
        printf("MEMBER_DATA_NOROUTE pkt=%u requestRouteTo=%u\r\n",
               (unsigned int)packet->ID,
               (unsigned int)targetID);
#endif
        sendRouteRequest(targetID);
        previousRouteReq = HAL_GetTick();
        sendRoutRequest = 1;
        getRoutReplay = 0;
    }
}

void processAckPacket(DataPacket *packet)
{
    (void)packet;
    previousNotGetACK = 0;
}

void processControlPacket(DataPacket *packet)
{
    /* 控制命令处理：转发或本地执行并回 ACK。 */
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

void processControlAckPacket(DataPacket *packet)
{
    /* 控制 ACK 处理：Sink 上报服务器，成员节点中继回传。 */
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

void processStatusPacket(DataPacket *packet)
{
    /* 状态包处理：Sink 消费，其他节点按路由转发。 */
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

void sniff(DataPacket *packet)
{
    /* 被动监听统计：记录转发、源包、ACK 与路由行为。 */
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

int findSniffID(uint8_t forwardID)
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




