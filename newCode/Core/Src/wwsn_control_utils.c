/* 控制模块：载荷编解码、命令解析、去重缓存、本地策略执行。 */

#include "wwsn_shared.h"

void sanitizeData(uint8_t *data, size_t len)
{
    /* 发送前将 0x00 统一替换为 0xFF，规避透传截断。 */
    for (size_t i = 0; i < len; i++)
    {
        if (data[i] == 0x00)
        {
            data[i] = 0xFF;
        }
    }
}

void restoreData(uint8_t *data, size_t len)
{
    /* 接收后将 0xFF 还原为 0x00。 */
    for (size_t i = 0; i < len; i++)
    {
        if (data[i] == 0xFF)
        {
            data[i] = 0x00;
        }
    }
}

void writeAsciiData(char *data, size_t len, const char *str)
{
    size_t slen = strlen(str);
    if (slen > len)
    {
        slen = len;
    }
    memset(data, 0xFF, len);
    memcpy(data, str, slen);
}

uint8_t cmdFromString(const char *cmd)
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

const char *cmdToString(uint8_t cmd)
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

int parseControlString(const char *str, uint8_t *seq, uint8_t *cmd, int32_t *p1, int32_t *p2)
{
    /* 解析控制字符串：C,seq,cmd,p1,p2。 */
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

uint8_t applyControlCommand(uint8_t cmd, int32_t p1, int32_t p2)
{
    /* 执行控制命令并返回执行结果（1 成功 / 0 失败）。 */
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

void fabricateSniffData(uint8_t *data)
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

void seedRandom(void)
{
    srand((unsigned int)(deviceUID ^ HAL_GetTick()));
}

uint32_t getDeviceUID(void)
{
#if defined(UID_BASE)
    return HAL_GetUIDw0() ^ HAL_GetUIDw1() ^ HAL_GetUIDw2();
#else
    return HAL_GetTick();
#endif
}

void initDeviceUID(void)
{
    deviceUID = getDeviceUID();
    snprintf(deviceUIDStr, sizeof(deviceUIDStr), "%08lX", (unsigned long)deviceUID);
    printf("DeviceUID=%s\r\n", deviceUIDStr);
}

void decideMalicious(void)
{
    /* 节点入网后按概率选择恶意行为模式。 */
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

void updateOnOff(void)
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

int isDuplicateRouteReq(uint8_t sourceID, uint8_t reqID)
{
    /* 路由请求去重，防止广播风暴。 */
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

void initRouteReqCache(void)
{
    for (int i = 0; i < ROUTE_REQ_CACHE_SIZE; i++)
    {
        routeReqCache[i].sourceID = NODE_ID_UNASSIGNED;
        routeReqCache[i].requestID = 0;
        routeReqCache[i].lastSeen = 0;
    }
}

int isDuplicateControl(uint8_t sourceID, uint8_t seq, uint8_t cmd)
{
    /* 控制命令去重，避免重复执行。 */
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

void initControlCache(void)
{
    for (int i = 0; i < CONTROL_CACHE_SIZE; i++)
    {
        controlCache[i].sourceID = NODE_ID_UNASSIGNED;
        controlCache[i].seq = 0;
        controlCache[i].cmd = 0;
        controlCache[i].lastSeen = 0;
    }
}



