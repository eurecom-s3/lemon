#define _GNU_SOURCE

#include <stdio.h>
#include <sched.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <sys/sysinfo.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>

#include "lemon.h"

static int nprocs = 0;
static pthread_t *threads = NULL;
static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int cpu;
    int priority;
} thread_params;

/*
 * Wrapper around sched_setscheduler that sets the scheduler to SCHED_FIFO,
 * sets the priority to the desired one and prints on error.
 * 
 * @param priority: The priority to set for the current process.
 * @return 0 on success, -1 on failure.
 */
static int set_priority(const int priority){
    const struct sched_param sparam = {
        .sched_priority = priority
    };

    if(sched_setscheduler(0, SCHED_FIFO, &sparam) == -1) {
        perror("Failed to set realtime scheduler class and priority");
        return -1;
    }
    return 0;
}

/*
 * @brief Entry point for each CPU stealer thread.
 *
 * Each thread tries to acquire a global mutex in a busy-loop using
 * pthread_mutex_trylock(). Once it succeeds, it immediately unlocks it and exits.
 * The purpose is to keep these threads active and scheduled on CPU cores.
 * 
 * @param arg: thread_params* The priority and CPU to set for the thread.
 */
static void* thread_function(void *arg) {
    const thread_params *tp = (const thread_params*) arg;
    cpu_set_t cpuset;
    int ret = EBUSY;

    set_priority(tp->priority);

    /* Set the CPU affinity for this thread */
    CPU_ZERO(&cpuset);
    CPU_SET(tp->cpu, &cpuset);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) == -1) {
        perror("Failed to pin CPU core for cpu stealer thread");
    }
    
    /* Infinite loop waiting fo the global mutex to be unlocked */
    while (ret == EBUSY) {
        ret = pthread_mutex_trylock(&mut);
    }
    
    /* Unlock the mutex if it was succesfully acquired */
    if (!ret) {
        pthread_mutex_unlock(&mut);
    }
    
    free((void*)tp);
    return NULL;
}

/*
 * @brief Wait for a specific number of CPU stealer threads to terminate.
 *
 * Unlocks the global mutex to let all threads exit their busy loops.
 * 
 * @param n: Number of threads to join.
 */
static int join_n_cpu_stealers(int n) {
    if(!threads) return -1;

    /* Unlock the global mutex */
    if(pthread_mutex_unlock(&mut)) {
        WARN("Fail to unlock mutex\n");
        return -1;
    }

    /* Join all the processes */
    for (int i = 0; i < n; i++) {
        const int ret = pthread_join(threads[i], NULL);
        if (ret) return -1;
    }

    free(threads);
    threads = NULL;
    return 0;
}

/*
 * @brief Create and run nprocs threads to occupy CPU cores.
 *
 * Allocates and launches nprocs threads that will spin on a locked mutex.
 * This prevents the OS from scheduling other tasks on those cores.
 * If thread creation fails midway, joins already created threads to clean up.
 * 
 * @param priority: The scheduling priority to set for the stealers threads.
 */
static int launch_cpu_stealers(const int priority) {
    int ret = 0;

    assert(threads == NULL);
    
    /* Allocate thread structs */
    nprocs = get_nprocs();
    threads = (pthread_t *)malloc((nprocs) * sizeof(pthread_t));
    if(!threads) {
        perror("Failed to allocate pthread_t structs");
        return errno;
    }

    /* Lock the global mutex */
    if((ret = pthread_mutex_lock(&mut))) {
        fprintf(stderr, "Fail to lock mutex\n");
        return ret;
    }

    /* Try to create nproc - 1 threads (the remaining one is the dumper)*/
    for (int i = 0; i < nprocs; i++) {
        thread_params *tp = (thread_params*) malloc(sizeof(thread_params));
        tp->cpu = i;
        tp->priority = priority;
        ret = pthread_create(&threads[i], NULL, thread_function, (void*) tp);
        if (ret) {
            /* Try to join the already created threads and silently ignore errors */
            join_n_cpu_stealers(i);
            return ret;
        }
    }

    return 0;
}

/*
 * @brief Set current process priority to highest real-time priority and launch CPU stealers.
 *
 * This function attempts to increase the scheduling priority of the calling process
 * by assigning it to the `SCHED_FIFO` real-time scheduling policy with the maximum
 * allowable priority.
 *
 * Allocates and launches nprocs threads that will spin on a locked mutex.
 * This prevents the OS from scheduling other tasks on those cores.
 * If thread creation fails midway, joins already created threads to clean up.
 * 
 * @return 0 on success, or -1 on failure.
 */
int increase_priority_and_launch_stealers() {
    const int max_sched = sched_get_priority_max(SCHED_FIFO);
    if(max_sched == -1) {
        perror("Failed to obtain max priority value for realtime process class");
        return -1;
    }

    if(set_priority(max_sched) == -1) {
        return -1;
    }

    launch_cpu_stealers(max_sched - 1);

    return 0;
}

/*
 * @brief Join all CPU stealer threads.
 *
 * Wrapper around join_n_cpu_stealers() that unlocks all of them.
 */
int join_cpu_stealers() {
    return join_n_cpu_stealers(nprocs);
}
