/* 路由模块：LoRa 参数配置、路由表维护、选路策略。 */

#include "wwsn_shared.h"

void configureModule(void)
{
    /* 统一配置节点的 LoRa 物理参数（地址、网络 ID、信道等）。 */
    cscxReg[3] = MacH;
    cscxReg[4] = MacL;
    cscxReg[5] = LORA_NETID;
    cscxReg[6] = LORA_REG0;
    cscxReg[7] = LORA_REG1;
    cscxReg[8] = channelID;
    cscxReg[9] = LORA_REG3;
}

uint8_t configureModuleRegisters(void)
{
    /* 进入配置模式，写寄存器并读回校验。 */
    uint8_t readLen = 0;
    uint8_t retry = 0;

    configureModule();

    HAL_GPIO_WritePin(M0_GPIO_Port, M0_Pin, GPIO_PIN_RESET);
    HAL_GPIO_WritePin(M1_GPIO_Port, M1_Pin, GPIO_PIN_SET);
    HAL_Delay(50);

    for (retry = 0; retry < 3; retry++)
    {
        memset(csrevReg, 0, sizeof(csrevReg));
        CS_Reg_Send_Data(cscxReg, sizeof(cscxReg));
        HAL_Delay(300);
        cstx_reg_Receive_Data(csrevReg, &readLen);
        if (readLen >= 10 && csrevReg[0] == 0xC1 && csrevReg[1] == 0x00 && csrevReg[2] == 0x07)
        {
            return 1;
        }
        HAL_Delay(50);
    }
    return 0;
}

int getEnvirRSSI(void)
{
    /* 读取当前信道环境噪声，输出噪声/SNR 诊断信息。 */
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

void addRoutingEntry(uint8_t destID, uint8_t nextHopID, uint8_t macHigh, uint8_t macLow,
                             uint8_t hop, int16_t rssi, int16_t noise)
{
    /* 若已存在同一目的节点，按“更少跳数/更高信号”更新，否则新增。 */
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

void deleteRoutingEntry(uint8_t routeIndex)
{
    /* 删除指定路由项并前移数组。 */
    for (int j = routeIndex; j < routingTableCount - 1; j++)
    {
        routingTable[j] = routingTable[j + 1];
    }
    if (routingTableCount > 0)
    {
        routingTableCount--;
    }
}

int findRoute(uint8_t destID)
{
    /* 查询目的节点路由，顺带清理超时条目。 */
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

void pruneRoutingTable(void)
{
    /* 定期清理路由表中过期条目。 */
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

int isBetterRoute(uint8_t newHop, int16_t newRssi, uint8_t oldHop, int16_t oldRssi)
{
    /* 选路策略：优先跳数，跳数相同再比较 RSSI。 */
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




