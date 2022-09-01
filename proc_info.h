#ifndef _PROC_INFO_H
#define _PROC_INFO_H

#include <ctype.h>

typedef struct
{
    // current pid
    unsigned int pid;
    // totoal cpu usage
    double percent_cpu;
    double percent_cpu_user;
    double percent_cpu_system;
    // totoal memory usage
    double percent_mem;
    double percent_cpu_process;
    double percent_mem_process;
    unsigned long long mem_total;
    unsigned long long mem_free;
    unsigned int cpu_count;
} proc_t;

/**
 * @brief Get the proc info object
 *
 * @param p
 */
void get_proc_info(proc_t *p);

/**
 * @brief Free memory
 *
 */
void free_memory();

#endif