#ifndef NETSNMP_SYSORTABLE_H
#define NETSNMP_SYSORTABLE_H

/* sysORTable 是一系列指向通过模块化方式实现 agent 功能的数据结构指针 */
struct sysORTable {
    char            *OR_descr;
    oid             *OR_oid;
    size_t           OR_oidlen;
    netsnmp_session *OR_sess;
    u_long           OR_uptime;
};

struct register_sysOR_parameters {
    char            *descr;
    oid             *name;
    size_t           namelen;
};

#define SYS_ORTABLE_REGISTERED_OK              0
#define SYS_ORTABLE_REGISTRATION_FAILED       -1
#define SYS_ORTABLE_UNREGISTERED_OK            0
#define SYS_ORTABLE_NO_SUCH_REGISTRATION      -1

#include <net-snmp/agent/agent_callbacks.h>

/*********************************************************************************************************
** 函数名称: REGISTER_SYSOR_TABLE
** 功能描述: 通过函数指定的参数向系统内注册一个 data_node 节点数据
** 输	 入: theoid - 指定的 oid 数据
**         : len - 指定的 oid 数据长度
**         : descr - 指定的 data_node 描述信息
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
#define REGISTER_SYSOR_TABLE(theoid, len, descr)           \
  do {                                                     \
    struct sysORTable t;                                   \
    t.OR_descr = NETSNMP_REMOVE_CONST(char *, descr);      \
    t.OR_oid = theoid;                                     \
    t.OR_oidlen = len;                                     \
    t.OR_sess = NULL;                                      \
    t.OR_uptime = 0;                                       \
    snmp_call_callbacks(SNMP_CALLBACK_APPLICATION,         \
                        SNMPD_CALLBACK_REQ_REG_SYSOR, &t); \
  } while(0);

/*********************************************************************************************************
** 函数名称: REGISTER_SYSOR_ENTRY
** 功能描述: 通过函数指定的参数向系统内注册一个 data_node 节点数据
** 输	 入: theoid - 指定的 oid 数据
**         : descr - 指定的 data_node 描述信息
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
#define REGISTER_SYSOR_ENTRY(theoid, descr)                     \
  REGISTER_SYSOR_TABLE(theoid, sizeof(theoid) / sizeof(oid),    \
                       descr)

/*********************************************************************************************************
** 函数名称: UNREGISTER_SYSOR_TABLE
** 功能描述: 遍历全局链表 table 并从中删除指定 oid 的 data_node 节点数据
** 输	 入: theoid - 指定的 oid 数据
**         : len - 指定的 oid 数据长度
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
#define UNREGISTER_SYSOR_TABLE(theoid, len)                     \
  do {                                                          \
    struct sysORTable t;                                        \
    t.OR_descr = NULL;                                          \
    t.OR_oid = theoid;                                          \
    t.OR_oidlen = len;                                          \
    t.OR_sess = NULL;                                           \
    t.OR_uptime = 0;                                            \
    snmp_call_callbacks(SNMP_CALLBACK_APPLICATION,              \
                        SNMPD_CALLBACK_REQ_UNREG_SYSOR, &t);    \
  } while(0);

/*********************************************************************************************************
** 函数名称: UNREGISTER_SYSOR_ENTRY
** 功能描述: 遍历全局链表 table 并从中删除指定 oid 的 data_node 节点数据
** 输	 入: theoid - 指定的 oid 数据
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
#define UNREGISTER_SYSOR_ENTRY(theoid)                          \
  UNREGISTER_SYSOR_TABLE(theoid, sizeof(theoid) / sizeof(oid))

/*********************************************************************************************************
** 函数名称: UNREGISTER_SYSOR_SESS
** 功能描述: 遍历全局链表 table 并从中删除指定会话的 data_node 节点数据
** 输	 入: sess - 指定的会话指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
#define UNREGISTER_SYSOR_SESS(sess)                             \
  snmp_call_callbacks(SNMP_CALLBACK_APPLICATION,                \
                      SNMPD_CALLBACK_REQ_UNREG_SYSOR_SESS,      \
                      sess);


#endif /* NETSNMP_SYSORTABLE_H */
