/*
 * wrapper to call all the mib module initialization functions 
 */

#include <net-snmp/agent/mib_module_config.h>
#include <net-snmp/net-snmp-config.h>
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "m2m.h"
#ifdef USING_IF_MIB_DATA_ACCESS_INTERFACE_MODULE
#include <net-snmp/data_access/interface.h>
#endif

#include "mibgroup/struct.h"
#include <net-snmp/agent/mib_modules.h>
#include <net-snmp/agent/table.h>
#include <net-snmp/agent/table_iterator.h>
#include "mib_module_includes.h"

static int need_shutdown = 0;

/*********************************************************************************************************
** 函数名称: _shutdown_mib_modules
** 功能描述: 注销当前系统使用的 mib 模块，和 init_mib_modules 相反
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int
_shutdown_mib_modules(int majorID, int minorID, void *serve, void *client)
{
    if (! need_shutdown) {
        netsnmp_assert(need_shutdown == 1);
    }
    else {
#include "mib_module_shutdown.h"

        need_shutdown = 0;
    }

    return SNMPERR_SUCCESS; /* callback rc ignored */
}

/*********************************************************************************************************
** 函数名称: init_mib_modules
** 功能描述: 初始化当前系统使用的 mib 模块，所有可以初始化的模块都包含在 mib_module_inits.h 文件中
**         : 我们在系统启动时，需要通过命令行 -I 参数指定我们实际需要初始化的模块名
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
init_mib_modules(void)
{
    static int once = 0;

#ifdef USING_IF_MIB_DATA_ACCESS_INTERFACE_MODULE
    netsnmp_access_interface_init();
#endif
#  include "mib_module_inits.h"

    need_shutdown = 1;

    if (once == 0) {
        int rc;
        once = 1;
        rc = snmp_register_callback( SNMP_CALLBACK_LIBRARY,
                                     SNMP_CALLBACK_SHUTDOWN,
                                     _shutdown_mib_modules,
                                     NULL);

        if( rc != SNMP_ERR_NOERROR )
            snmp_log(LOG_ERR, "error registering for SHUTDOWN callback "
                     "for mib modules\n");
    }
}
