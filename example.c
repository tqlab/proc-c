/**
 * @file main.c
 * @author Tqlab
 * @brief Only for test
 * @version 0.1
 * @date 2022-08-31
 *
 * @copyright Copyright (c) 2022
 *
 */
#include "proc_info.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **agrs)
{
    int i;
    proc_t p;
    while (1)
    {
        size_t len = 100 * 1024 * 1024;
        void *ptr = malloc(len);
        memset(ptr, 1, len);
        free(ptr);

        get_proc_info(&p);
        printf("cpus: %d, id: %d, total:%5.2f, user:%5.2f, system:%5.2f, process cpu:%5.2f, process mem:%5.2f, totoal mem:%5.2f, mem:%lld, free mem:%lld\n",
               p.cpu_count, p.pid, p.percent_cpu, p.percent_cpu_user, p.percent_cpu_system, p.percent_cpu_process,
               p.percent_mem_process, p.percent_mem, p.mem_total, p.mem_free);
        sleep(1);
    }
    free_memory();

    return 1;
}