#include <net-snmp/net-snmp-config.h>

#include <stdio.h>
#if HAVE_DIRENT_H
#include <dirent.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <net-snmp/agent/netsnmp_close_fds.h>

/**
 * Close all file descriptors larger than @fd.
 */
/*********************************************************************************************************
** 函数名称: netsnmp_close_fds
** 功能描述: 关闭所有大于指定的值的文件描述符
** 输	 入: fd - 指定的值
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netsnmp_close_fds(int fd)
{
#if defined(HAVE_FORK)
    DIR            *dir;
    struct dirent  *ent;
    int             i, largest_fd = -1;

    if (fd < -1)
        fd = -1;

    if ((dir = opendir("/proc/self/fd"))) {
        while ((ent = readdir(dir))) {
            if (sscanf(ent->d_name, "%d", &i) == 1) {
                if (i > largest_fd)
                    largest_fd = i;
            }
        }
        closedir(dir);
    } else {
        largest_fd = getdtablesize() - 1;
    }

    for (i = largest_fd; i > fd && i >= 0; i--)
        close(i);
#endif
}
