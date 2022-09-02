#include "proc_info.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#if defined __APPLE__

#include <stdbool.h>
#include <libproc.h>
#include <mach/mach.h>
#include <sys/proc.h>
#include <sys/sysctl.h>

static long cp_time[CPU_STATE_MAX];
static long cp_old[CPU_STATE_MAX];
static long cp_diff[CPU_STATE_MAX];
static int cpu_states[CPU_STATE_MAX];
host_cpu_load_info_data_t cpuload;

typedef struct
{
    unsigned int cpu_count;
    host_basic_info_data_t host_info;
    processor_cpu_load_info_t prev_load;
    processor_cpu_load_info_t current_load;

    uint64_t utime;
    uint64_t stime;

} process_basic_t;

static process_basic_t process_ptr;
static mach_port_t libtop_port;
static bool inited = false;

static unsigned int get_cpu_load_info(processor_cpu_load_info_t *p)
{
    mach_msg_type_number_t info_size = sizeof(processor_cpu_load_info_t);
    unsigned int cpu_count;
    if (0 != host_processor_info(libtop_port, PROCESSOR_CPU_LOAD_INFO, &cpu_count, (processor_info_array_t *)p, &info_size))
    {
        printf("unable to retrieve CPU info\n");
    }
    return cpu_count;
}

static void get_host_info(host_basic_info_data_t *p)
{
    mach_msg_type_number_t info_size = HOST_BASIC_INFO_COUNT;
    if (0 != host_info(libtop_port, HOST_BASIC_INFO, (host_info_t)p, &info_size))
    {
        printf("unable to retrieve host info\n");
    }
}

static long percentages(int cnt, int *out, long *new, long *old, long *diffs)
{
    register int i;
    register long change;
    register long total_change;
    register long *dp;
    long half_total;

    /* initialization */
    total_change = 0;
    dp = diffs;

    for (i = 0; i < cnt; i++)
    {
        if ((change = *new - *old) < 0)
        {
            change = (int)((unsigned long)*new - (unsigned long)*old);
        }
        total_change += (*dp++ = change);
        *old++ = *new ++;
    }

    if (total_change == 0)
    {
        total_change = 1;
    }

    half_total = total_change / 2l;
    for (i = 0; i < cnt; i++)
    {
        *out++ = (int)((*diffs++ * 10000 + half_total) / total_change);
    }

    return (total_change);
}

/**
static size_t get_memory_process()
{
    struct rusage rusage;
    getrusage(RUSAGE_SELF, &rusage);
    return (size_t)rusage.ru_maxrss;
}
*/

static void init_check()
{
    if (inited)
    {
        return;
    }
    libtop_port = mach_host_self();
    process_ptr.cpu_count = get_cpu_load_info(&process_ptr.prev_load);
    get_host_info(&process_ptr.host_info);
    get_cpu_load_info(&process_ptr.current_load);

    inited = true;
}

void get_proc_info(proc_t *p)
{
    init_check();

    process_ptr.prev_load = process_ptr.current_load;
    get_cpu_load_info(&process_ptr.current_load);
    unsigned int cpu_count = process_ptr.cpu_count;

    uint64_t global_diff = 0;
    for (unsigned int i = 0; i < cpu_count; ++i)
    {
        for (size_t j = 0; j < CPU_STATE_MAX; ++j)
        {
            global_diff += process_ptr.current_load[i].cpu_ticks[j] - process_ptr.prev_load[i].cpu_ticks[j];
        }
    }

    struct proc_taskinfo pti;
    pid_t pid = getpid();

    if (sizeof(pti) == proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &pti, sizeof(pti)))
    {
        if (0 != process_ptr.utime || 0 != process_ptr.stime)
        {
            uint64_t diff = (pti.pti_total_user - process_ptr.utime) + (pti.pti_total_system - process_ptr.stime);
            p->percent_cpu_process = (diff * cpu_count) / (double)(global_diff * 100000.0);
        }

        // size_t mem = get_memory_process();
        p->percent_mem_process = (double)pti.pti_resident_size / (double)process_ptr.host_info.max_mem * 100;
        process_ptr.stime = pti.pti_total_system;
        process_ptr.utime = pti.pti_total_user;
        p->pid = pid;
    }

    p->cpu_count = cpu_count;
    p->mem_total = process_ptr.host_info.max_mem;

    //

    int i;
    unsigned int load_count = HOST_CPU_LOAD_INFO_COUNT;

    if (host_statistics(libtop_port, HOST_CPU_LOAD_INFO, (host_info_t)&cpuload, &load_count) == KERN_SUCCESS)
    {
        for (i = 0; i < CPU_STATE_MAX; i++)
        {
            cp_time[i] = cpuload.cpu_ticks[i];
        }
    }
    percentages(CPU_STATE_MAX, cpu_states, cp_time, cp_old, cp_diff);

    //
    int mib[6];
    mib[0] = CTL_HW;
    mib[1] = HW_PAGESIZE;

    int pagesize;
    size_t length;
    length = sizeof(pagesize);
    if (sysctl(mib, 2, &pagesize, &length, NULL, 0) < 0)
    {
        fprintf(stderr, "getting page size");
        return;
    }

    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;

    vm_statistics64_data_t vmstat;
    if (host_statistics64(libtop_port, HOST_VM_INFO64, (host_info64_t)&vmstat, &count) != KERN_SUCCESS)
    {
        fprintf(stderr, "Failed to get VM statistics.");
        return;
    }
    natural_t app_mem = vmstat.internal_page_count - vmstat.purgeable_count;
    natural_t used_mem = app_mem + vmstat.wire_count + vmstat.compressor_page_count;
    
    natural_t total_mem = vmstat.free_count + vmstat.wire_count + vmstat.active_count + vmstat.inactive_count + vmstat.speculative_count +
                          vmstat.throttled_count + vmstat.compressor_page_count;

    p->percent_mem = used_mem / (double)(total_mem)*100;
    p->percent_cpu_user = cpu_states[0] / 100.0;
    p->percent_cpu_system = cpu_states[1] / 100.0;
    p->percent_cpu = p->percent_cpu_user + p->percent_cpu_system;
    p->mem_free = (1 - p->percent_mem / 100) * p->mem_total;
}

void free_memory() {}
#else

#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/times.h>
#include <time.h>

typedef enum
{
    SUCCESS = 0,
    FAILURE = -1,
} result_t;

#define PATH_MAX 4096
#define LINE_BUFFER_SIZE 1024
#define PROCESS_NAME_LEN 16
#define SWAP(a, b)     \
    {                  \
        void *tmp = a; \
        a = b;         \
        b = tmp;       \
    }

typedef struct
{
    uint64_t user;
    uint64_t nice;
    uint64_t system;
    uint64_t idle;
    uint64_t iowait;
    uint64_t irq;
    uint64_t softirq;
    uint64_t steal;
    uint64_t guest;
    uint64_t guest_nice;
} cputime_t;

typedef struct
{
    int pid;
    int tid;
    char comm[PROCESS_NAME_LEN];
    char state;
    uint64_t load;
    uint64_t utime;
    uint64_t stime;
    uint64_t cutime;
    uint64_t cstime;
    int64_t priority;
    int64_t nice;
} process_t;

typedef struct
{
    int cpu_num;
    cputime_t *times;
    process_t *proc;
} cpu_t;

typedef struct
{
    unsigned int cpu_count;
    cpu_t *after;
    cpu_t *before;

    uint64_t utime;
    uint64_t stime;
} process_basic_t;

static process_basic_t *process_ptr = NULL;
static void *xmalloc(size_t size)
{
    void *p = malloc(size);
    if (p == NULL)
    {
        exit(EXIT_FAILURE);
    }
    return p;
}

static result_t read_stat(cpu_t *cpu)
{
    cputime_t *work;
    FILE *file;
    char line[LINE_BUFFER_SIZE];
    file = fopen("/proc/stat", "rb");
    if (file == NULL)
    {
        return FAILURE;
    }
    // line example: cpu  756661 39490 243001 74458419 4799 0 9257 0 0 0
    if (fgets(line, sizeof(line), file) == NULL)
    {
        goto error;
    }
    memset(cpu->times, 0, sizeof(cputime_t) * cpu->cpu_num);
    work = &cpu->times[cpu->cpu_num];
    if (sscanf(line, "cpu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
               &work->user, &work->nice, &work->system, &work->idle,
               &work->iowait, &work->irq, &work->softirq, &work->steal,
               &work->guest, &work->guest_nice) < 4)
    {
        goto error;
    }

    if (cpu->cpu_num > 1)
    {
        int i;
        for (i = 0; i < cpu->cpu_num; i++)
        {
            // line example: cpu0 94712 4820 29235 9309195 592 0 336 0 0 0
            if (fgets(line, sizeof(line), file) == NULL)
            {
                goto error;
            }
            work = &cpu->times[i];
            if (sscanf(line, "cpu%*u %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
                       &work->user, &work->nice, &work->system, &work->idle,
                       &work->iowait, &work->irq, &work->softirq, &work->steal,
                       &work->guest, &work->guest_nice) < 4)
            {
                goto error;
            }
        }
    }

    return SUCCESS;

error:
    fclose(file);
    return FAILURE;
}

static result_t parse_stat(char *line, process_t *proc)
{
    char *tmp;
    int len;
    int n;
    line = strchr(line, '(') + 1;
    tmp = strchr(line, ')');
    len = tmp - line;
    if (len > sizeof(proc->comm))
    {
        len = sizeof(proc->comm) - 1;
    }
    memcpy(proc->comm, line, len);
    proc->comm[len] = 0;
    line = tmp + 2;

    n = sscanf(line,
               // state
               // ppid pgid sid tty_nr tty_pgrp
               // flags min_flt cmin_flt maj_flt cmaj_flt
               // utime stime cutime cstime
               // priority nice
               "%c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu %lu %lu %ld %ld ",
               &proc->state,
               &proc->utime,
               &proc->stime,
               &proc->cutime,
               &proc->cstime,
               &proc->priority,
               &proc->nice);
    if (n != 7)
    {
        return FAILURE;
    }
    return SUCCESS;
}

static result_t read_pid_stat(process_t *proc, int pid)
{
    char path[PATH_MAX];
    FILE *file;
    char line[LINE_BUFFER_SIZE];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    file = fopen(path, "rb");
    if (file == NULL)
    {
        return FAILURE;
    }
    // line example: 12 (ksoftirqd/0) S 2 0 0 0 -1 69238848 0 0 0 0 11 37 0 0 20 0 1 0 16 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    if (fgets(line, sizeof(line), file) == NULL)
    {
        goto error;
    }
    fclose(file);

    memset(proc, 0, sizeof(process_t));
    proc->pid = pid;

    return parse_stat(line, proc);

error:
    fclose(file);
    return FAILURE;
}

static uint64_t get_cpu_total(cputime_t *time)
{
    return time->user + time->nice + time->system + time->idle + time->iowait + time->irq + time->softirq + time->steal + time->guest + time->guest_nice;
}

static uint64_t get_cpu_user(cputime_t *time)
{
    return time->user + time->nice;
}

static uint64_t get_cpu_system(cputime_t *time)
{
    return time->system + time->irq + time->softirq;
}

static uint64_t get_cpu_idle(cputime_t *time)
{
    return time->iowait + time->idle;
}

static void get_cpu_diff(cputime_t *before, cputime_t *after, cputime_t *diff)
{
    uint64_t tmp;

#define DIFF(x)                      \
    {                                \
        tmp = after->x - before->x;  \
        diff->x = tmp < 0 ? 0 : tmp; \
    }

    DIFF(user);
    DIFF(nice);
    DIFF(system);
    DIFF(idle);
    DIFF(iowait);
    DIFF(irq);
    DIFF(softirq);
    DIFF(steal);
    DIFF(guest);
    DIFF(guest_nice);

#undef DIFF
}

static unsigned long long get_memory_total()
{
    struct sysinfo info;
    sysinfo(&info);
    long long total_mem = info.totalram;
    // total_mem += memInfo.totalswap;
    total_mem *= info.mem_unit;
    return (unsigned long long)total_mem;
}

static unsigned long long get_memory_free()
{
    struct sysinfo info;
    sysinfo(&info);
    long long freeram = info.freeram * info.mem_unit;
    return (unsigned long long)freeram;
}

static unsigned long get_memory_process()
{
    int error_n = -1;

    FILE *f = fopen("/proc/self/status", "r");

    if (f == NULL)
    {
        return 0;
    }

    uint64_t memusage = 0;

    for (;;)
    {
        char buf[512];
        char key[100];
        unsigned long long val;

        if (fgets(buf, sizeof(buf), f) == NULL)
            goto error;

        int res = sscanf(buf, "%99[^:]: %Lu", key, &val);

        if (res == 2 && strcmp(key, "VmRSS") == 0)
        {
            memusage = val << 10;
            break;
        }
    }

    fclose(f);
    return memusage;

error:
    fprintf(stderr, "Error: unable to read /proc/self/status (error %i)\n", error_n);
    fclose(f);
    return 0;
}

static void get_cpu_result(proc_t *p, cpu_t *before, cpu_t *after)
{
    //
    // us = (user + nice ) / cpu_total * 100%
    // sy = (systime + irq + softirq ) / cpu_total * 100%
    //
    cputime_t diff;
    int num = before->cpu_num;
    get_cpu_diff(&before->times[num], &after->times[num], &diff);

    uint64_t total = get_cpu_total(&diff);
    if (total == 0)
    {
        total = 1;
    }

    uint64_t idle = get_cpu_idle(&diff);
    uint64_t user = get_cpu_user(&diff);
    uint64_t system = get_cpu_system(&diff);

    process_t *proc = after->proc;

    long clk_tck = sysconf(_SC_CLK_TCK);

    proc->load = (proc->utime + proc->stime) - (before->proc->utime + before->proc->stime);

    p->percent_cpu_process = (double)(clk_tck * proc->load * num) / total;

    p->percent_cpu_user = (double)(user) / total * 100;
    p->percent_cpu_system = (double)(system) / total * 100;
    p->percent_cpu = p->percent_cpu_user + p->percent_cpu_system;
}

static void *new_cpu_t(int num)
{
    cpu_t *cpu;
    cpu = xmalloc(sizeof(cpu_t));
    cpu->cpu_num = num;
    cpu->times = xmalloc((num + 1) * sizeof(cputime_t));
    cpu->proc = xmalloc(sizeof(process_t));
    return cpu;
}

void get_proc_info(proc_t *p)
{
    int pid = getpid();

    if (process_ptr == NULL)
    {
        process_ptr = xmalloc(sizeof(process_basic_t));
        cpu_t *after;
        cpu_t *before;

        int num = get_nprocs();
        after = new_cpu_t(num);
        before = new_cpu_t(num);

        process_ptr->after = after;
        process_ptr->before = before;
        process_ptr->cpu_count = num;

        if (read_stat(before) != SUCCESS || read_pid_stat(before->proc, pid) != SUCCESS)
        {
            return;
        }
    }

    if (read_stat(process_ptr->after) != SUCCESS || read_pid_stat(process_ptr->after->proc, pid) != SUCCESS)
    {
        return;
    }
    get_cpu_result(p, process_ptr->before, process_ptr->after);
    SWAP(process_ptr->before, process_ptr->after);
    p->pid = pid;
    p->mem_total = get_memory_total();
    p->mem_free = get_memory_free();
    p->percent_mem = (double)(p->mem_total - p->mem_free) / (double)p->mem_total * 100;
    p->percent_mem_process = (double)(get_memory_process()) / (double)p->mem_total * 100;
    p->cpu_count = process_ptr->cpu_count;
}

void free_memory()
{
    if (process_ptr != NULL)
    {

        if (process_ptr->after != NULL)
        {
            free(process_ptr->after);
        }
        if (process_ptr->before != NULL)
        {
            free(process_ptr->before);
        }
        free(process_ptr);
    }
}

#endif