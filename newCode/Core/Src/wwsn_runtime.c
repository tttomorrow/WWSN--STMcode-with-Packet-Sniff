/* 运行时模块：显示刷新、传感上报、WiFi 连接、Sink 端节点管理。 */

#include "wwsn_shared.h"

void updateNodeDisplay(void)
{
    OLED_ShowString(100, 0, "   ");
    sprintf(nodeIDStr, "%d", nodeID);
    OLED_ShowString(100, 0, (unsigned char *)nodeIDStr);
}

#if NODE_ROLE_SINK
void updateSinkJoinDebugDisplay(void)
{
    snprintf((char *)disOLED, sizeof(disOLED), "JR:%03u JA:%03u",
             (unsigned int)sinkJoinReqRxCount,
             (unsigned int)sinkJoinAssignTxCount);
    OLED_ShowString(0, 6, "                ");
    OLED_ShowString(0, 6, disOLED);
}
#endif

void sendSensorData(void)
{
    /* 周期采集温湿度并上报，同时携带监听统计信息。 */
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
        if (!NODE_ROLE_SINK)
        {
            memset(disOLED, 0, sizeof(disOLED));
            snprintf((char *)disOLED, sizeof(disOLED), "T:%d.%dC H:%d.%dR",
                     Dht11data[2], Dht11data[3], Dht11data[0], Dht11data[1]);
            OLED_ShowString(0, 6, "                ");
            OLED_ShowString(0, 6, disOLED);
        }

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

            sendDataPacket(&datapacket);
            previousNotGetACK++;
        }
        else
        {
            sendRouteRequest(targetID);
            previousRouteReq = HAL_GetTick();
            sendRoutRequest = 1;
            getRoutReplay = 0;
        }

        if (previousNotGetACK >= ACK_MISS_THRESHOLD && routeIndex != -1)
        {
            deleteRoutingEntry((uint8_t)routeIndex);
            previousNotGetACK = 0;
        }
    }
    else
    {
        if (!NODE_ROLE_SINK)
        {
            OLED_ShowString(0, 6, "DHT READ ERR    ");
        }
    }
#else
    (void)roundTime;
#endif
}

#if NODE_ENABLE_WIFI
void connectServer(void)
{
    uint8_t tryCount = 0;
    if (WIFI_ALLOW_SERIAL_FALLBACK && linkMode == LINK_MODE_SERIAL)
    {
        return;
    }

    res = 1;
    for (tryCount = 0; tryCount < WIFI_CONNECT_TRY_MAX && res; tryCount++)
    {
        res = WIFI_Dect((uint8_t *)WIFI_SSID, (uint8_t *)WIFI_PASSWORD);
        HAL_Delay(200);
    }
    if (res)
    {
        linkMode = WIFI_ALLOW_SERIAL_FALLBACK ? LINK_MODE_SERIAL : LINK_MODE_AUTO;
        return;
    }

    HAL_GPIO_WritePin(LED1_GPIO_Port, LED1_Pin, GPIO_PIN_RESET);

    res = 1;
    for (tryCount = 0; tryCount < SERVER_CONNECT_TRY_MAX && servernotok; tryCount++)
    {
        res = ESP8266_CONNECT_SERVER((uint8_t *)WIFI_SERVER_IP, (uint8_t *)WIFI_SERVER_PORT);
        HAL_Delay(1000);
    }

    if (!servernotok)
    {
        linkMode = LINK_MODE_WIFI;
    }
    else
    {
        linkMode = WIFI_ALLOW_SERIAL_FALLBACK ? LINK_MODE_SERIAL : LINK_MODE_AUTO;
    }
}
#endif

#if NODE_ROLE_SINK
uint8_t assignNodeID(uint32_t uid)
{
    /* Sink 按 UID 分配网络 ID；已登记节点复用原 ID。 */
    for (int i = 0; i < nodeRegistryCount; i++)
    {
        if (nodeRegistry[i].uid == uid)
        {
            nodeRegistry[i].lastSeen = HAL_GetTick();
            printf("JOIN_REG_HIT uid=%08lX id=%u\r\n",
                   (unsigned long)uid,
                   (unsigned int)nodeRegistry[i].nodeID);
            return nodeRegistry[i].nodeID;
        }
    }

    if (nodeRegistryCount >= MAX_NODES || nextNodeID == NODE_ID_UNASSIGNED)
    {
        printf("JOIN_REG_FULL uid=%08lX count=%u next=%u\r\n",
               (unsigned long)uid,
               (unsigned int)nodeRegistryCount,
               (unsigned int)nextNodeID);
        return NODE_ID_UNASSIGNED;
    }

    nodeRegistry[nodeRegistryCount].uid = uid;
    nodeRegistry[nodeRegistryCount].nodeID = nextNodeID;
    nodeRegistry[nodeRegistryCount].lastSeen = HAL_GetTick();
    printf("JOIN_REG_NEW uid=%08lX id=%u slot=%u\r\n",
           (unsigned long)uid,
           (unsigned int)nextNodeID,
           (unsigned int)nodeRegistryCount);
    nodeRegistryCount++;
    nextNodeID++;
    return nodeRegistry[nodeRegistryCount - 1].nodeID;
}

void handleTcpCommandBuffer(const uint8_t *buf)
{
    /* 解析服务器下发的 CTRL 命令并转发到无线网络。 */
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



