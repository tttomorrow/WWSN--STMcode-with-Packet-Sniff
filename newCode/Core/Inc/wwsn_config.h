#ifndef WWSN_CONFIG_H
#define WWSN_CONFIG_H

/* 节点角色配置：1=Sink，0=Member。只在此处修改。 */
#ifndef NODE_ROLE_SINK
#define NODE_ROLE_SINK 0
#endif

/* 功能开关与角色联动。 */
#ifndef NODE_ENABLE_SENSOR
#define NODE_ENABLE_SENSOR (!NODE_ROLE_SINK)
#endif

#ifndef NODE_ENABLE_WIFI
#define NODE_ENABLE_WIFI NODE_ROLE_SINK
#endif

#endif
