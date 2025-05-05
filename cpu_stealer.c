#include <stdio.h>
#include <sched.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <sys/sysinfo.h>
#include <stdlib.h>
#include <unistd.h>

static int nprocs = 0;
static pthread_t *threads = NULL;
static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

/*
 * increase_priority() - Elevates the current process to the highest real-time priority.
 *
 * This function attempts to increase the scheduling priority of the calling process
 * by assigning it to the `SCHED_FIFO` real-time scheduling policy with the maximum
 * allowable priority.
 *
 * Returns 0 on success, or an error code (from errno) on failure.
 */
int increase_priority(void) {
    struct sched_param sparam;
    int max_sched;

    max_sched = sched_get_priority_max(SCHED_FIFO);
    if(max_sched < 0) {
        perror("Fail to obtain max priority value for realtime process class");
        return errno;
    }

    sparam.sched_priority = max_sched;
    if(sched_setscheduler(0, SCHED_FIFO, &sparam)) {
        perror("Fail to set realtime scheduler class");
        return errno;
    }

    return 0;
}

/*
 * thread_function() - Entry point for each CPU stealer thread.
 * @arg: Unused.
 *
 * Each thread tries to acquire a global mutex in a busy-loop using
 * pthread_mutex_trylock(). Once it succeeds, it immediately unlocks it and exits.
 * The purpose is to keep these threads active and scheduled on CPU cores.
 */
static void* thread_function(void* arg) {
    int ret = EBUSY;
    
    /* Infinite loop waiting fo the global mutex to be unlocked */
    while (ret == EBUSY) {
        ret = pthread_mutex_trylock(&mut);
    }
    
    /* Unlock in case of error */
    if (!ret) {
        pthread_mutex_unlock(&mut);
    }
    
    return NULL;
}

/*
 * join_n_cpu_stealers() - Wait for a specific number of CPU stealer threads to terminate.
 * @n: Number of threads to join.
 *
 * Unlocks the global mutex to let all threads exit their busy loops.
 */
static int join_n_cpu_stealers(int n) {
    int ret = 0;
    if(!threads) return 0;

    /* Unlock the global mutex */
    if((ret = pthread_mutex_unlock(&mut))) {
        fprintf(stderr, "Fail to unlock mutex\n");
    }

    /* Join all the processes */
    for (int i = 0; i < n - 1; i++) {
        ret = pthread_join(threads[i], NULL);
        if (ret) continue;
    }

    free(threads);
    threads = NULL;
    return ret;
}

/*
 * launch_cpu_stealers() - Create and run nprocs - 1 threads to occupy CPU cores.
 *
 * Allocates and launches (nprocs - 1) threads that will spin on a locked mutex.
 * This prevents the OS from scheduling other tasks on those cores.
 * If thread creation fails midway, joins already created threads to clean up.
 */
int launch_cpu_stealers() {
    int ret = 0;

    assert(threads == NULL);
    
    /* Allocate thread structs */
    nprocs = get_nprocs();
    threads = (pthread_t *)malloc((nprocs - 1) * sizeof(pthread_t));
    if(!threads) {
        perror("Fail to allocate pthread_t structs");
        return errno;
    }

    /* Lock the global mutex */
    if((ret = pthread_mutex_lock(&mut))) {
        fprintf(stderr, "Fail to lock mutex\n");
        return ret;
    }

    /* Try to create nproc - 1 threads (the remaining one is the dumper)*/
    for (int i = 0; i < nprocs - 1; i++) {
        ret = pthread_create(&threads[i], NULL, thread_function, NULL);
        if (ret) {
            /* Try to join the already created threads and silently ignore errors */
            join_n_cpu_stealers(i);
            return ret;
        }
    }

    return 0;
}

/*
 * join_cpu_stealers() - Join all CPU stealer threads.
 *
 * Wrapper around join_n_cpu_stealers() using the global nprocs value.
 */
int join_cpu_stealers() {
    return join_n_cpu_stealers(nprocs - 1);
}