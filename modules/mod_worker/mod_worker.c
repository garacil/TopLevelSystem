/*
 * Author: Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/*
 * mod_worker — Thread pool for background tasks
 *
 * Named worker pools that execute path calls asynchronously.
 * Submit jobs with a target path, track status, cancel pending.
 * Thread-safe with configurable pool sizes.
 *
 * Config:
 *   [mod_worker]
 *   max_pools = 16
 *   default_threads = 4
 *   max_jobs = 1000
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include "portal/portal.h"

#define WORKER_MAX_POOLS     16
#define WORKER_DEFAULT_THR   4
#define WORKER_MAX_JOBS      1000

typedef enum {
    JOB_PENDING = 0,
    JOB_RUNNING,
    JOB_DONE,
    JOB_FAILED,
    JOB_CANCELLED
} job_status_t;

typedef struct worker_job {
    int              id;
    char             path[PORTAL_MAX_PATH_LEN];
    job_status_t     status;
    int64_t          submitted;
    int64_t          finished;
    struct worker_job *next;
} worker_job_t;

typedef struct {
    char             name[64];
    int              thread_count;
    pthread_t       *threads;
    pthread_mutex_t  lock;
    pthread_cond_t   cond;
    worker_job_t    *head;
    worker_job_t    *tail;
    int              pending;
    int64_t          total_submitted;
    int64_t          total_completed;
    int64_t          total_failed;
    int              active;
    int              shutdown;
} worker_pool_t;

static portal_core_t *g_core = NULL;
static worker_pool_t  g_pools[WORKER_MAX_POOLS];
static int            g_pool_count = 0;
static int            g_max_pools = WORKER_MAX_POOLS;
static int            g_default_threads = WORKER_DEFAULT_THR;
static int            g_job_id = 0;
static pthread_mutex_t g_global_lock = PTHREAD_MUTEX_INITIALIZER;

static portal_module_info_t info = {
    .name = "worker", .version = "1.0.0",
    .description = "Thread pool for background tasks",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

static worker_pool_t *find_pool(const char *name)
{
    for (int i = 0; i < g_pool_count; i++)
        if (g_pools[i].active && strcmp(g_pools[i].name, name) == 0)
            return &g_pools[i];
    return NULL;
}

/* Worker thread function */
static void *worker_thread(void *arg)
{
    worker_pool_t *pool = (worker_pool_t *)arg;

    while (1) {
        pthread_mutex_lock(&pool->lock);
        while (!pool->head && !pool->shutdown)
            pthread_cond_wait(&pool->cond, &pool->lock);

        if (pool->shutdown && !pool->head) {
            pthread_mutex_unlock(&pool->lock);
            break;
        }

        /* Dequeue job */
        worker_job_t *job = pool->head;
        if (job) {
            pool->head = job->next;
            if (!pool->head) pool->tail = NULL;
            pool->pending--;
            job->status = JOB_RUNNING;
        }
        pthread_mutex_unlock(&pool->lock);

        if (!job) continue;

        /* Execute: send CALL to the target path */
        portal_msg_t *msg = portal_msg_alloc();
        portal_resp_t *resp = portal_resp_alloc();
        int rc = -1;
        if (msg && resp) {
            portal_msg_set_path(msg, job->path);
            portal_msg_set_method(msg, PORTAL_METHOD_CALL);
            rc = g_core->send(g_core, msg, resp);
            portal_msg_free(msg);
            portal_resp_free(resp);
        }

        pthread_mutex_lock(&pool->lock);
        job->finished = (int64_t)time(NULL);
        if (rc == 0) {
            job->status = JOB_DONE;
            pool->total_completed++;
        } else {
            job->status = JOB_FAILED;
            pool->total_failed++;
        }
        pthread_mutex_unlock(&pool->lock);

        g_core->event_emit(g_core, "/events/worker/complete",
                           job->path, strlen(job->path));
        g_core->log(g_core, PORTAL_LOG_DEBUG, "worker",
                    "Job #%d [%s] %s", job->id, job->path,
                    rc == 0 ? "completed" : "failed");
        free(job);
    }
    return NULL;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_pools, 0, sizeof(g_pools));
    g_pool_count = 0;
    g_job_id = 0;

    const char *v;
    if ((v = core->config_get(core, "worker", "max_pools")))
        g_max_pools = atoi(v);
    if ((v = core->config_get(core, "worker", "default_threads")))
        g_default_threads = atoi(v);

    core->path_register(core, "/worker/resources/status", "worker");
    core->path_set_access(core, "/worker/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/worker/resources/status", "Thread pool: pool count, total threads");
    core->path_register(core, "/worker/resources/pools", "worker");
    core->path_set_access(core, "/worker/resources/pools", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/worker/resources/pools", "List worker pools with stats");
    core->path_register(core, "/worker/functions/create", "worker");
    core->path_set_access(core, "/worker/functions/create", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/worker/functions/create", "Create pool. Headers: name, threads");
    core->path_register(core, "/worker/functions/submit", "worker");
    core->path_set_access(core, "/worker/functions/submit", PORTAL_ACCESS_RW);
    core->path_register(core, "/worker/functions/destroy", "worker");
    core->path_set_access(core, "/worker/functions/destroy", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "worker",
              "Worker pools ready (max: %d pools, default: %d threads)",
              g_max_pools, g_default_threads);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    /* Shutdown all pools */
    for (int i = 0; i < g_pool_count; i++) {
        if (!g_pools[i].active) continue;
        pthread_mutex_lock(&g_pools[i].lock);
        g_pools[i].shutdown = 1;
        pthread_cond_broadcast(&g_pools[i].cond);
        pthread_mutex_unlock(&g_pools[i].lock);

        for (int t = 0; t < g_pools[i].thread_count; t++)
            pthread_join(g_pools[i].threads[t], NULL);

        /* Free remaining jobs */
        worker_job_t *j = g_pools[i].head;
        while (j) { worker_job_t *n = j->next; free(j); j = n; }
        free(g_pools[i].threads);
        pthread_mutex_destroy(&g_pools[i].lock);
        pthread_cond_destroy(&g_pools[i].cond);
    }

    core->path_unregister(core, "/worker/resources/status");
    core->path_unregister(core, "/worker/resources/pools");
    core->path_unregister(core, "/worker/functions/create");
    core->path_unregister(core, "/worker/functions/submit");
    core->path_unregister(core, "/worker/functions/destroy");
    core->log(core, PORTAL_LOG_INFO, "worker", "Worker pools unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[8192];
    int n;

    if (strcmp(msg->path, "/worker/resources/status") == 0) {
        int active = 0;
        int64_t tc = 0, tf = 0, tp = 0;
        for (int i = 0; i < g_pool_count; i++) {
            if (!g_pools[i].active) continue;
            active++;
            tc += g_pools[i].total_completed;
            tf += g_pools[i].total_failed;
            tp += g_pools[i].total_submitted;
        }
        n = snprintf(buf, sizeof(buf),
            "Worker Pools\n"
            "Pools: %d active (max %d)\n"
            "Total submitted: %lld\n"
            "Total completed: %lld\n"
            "Total failed: %lld\n",
            active, g_max_pools,
            (long long)tp, (long long)tc, (long long)tf);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/worker/resources/pools") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Worker Pools:\n");
        for (int i = 0; i < g_pool_count; i++) {
            if (!g_pools[i].active) continue;
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "  %-16s threads: %d  pending: %d  done: %lld  failed: %lld\n",
                g_pools[i].name, g_pools[i].thread_count, g_pools[i].pending,
                (long long)g_pools[i].total_completed,
                (long long)g_pools[i].total_failed);
        }
        if (g_pool_count == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/worker/functions/create") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *thr_s = get_hdr(msg, "threads");
        if (!name) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: name header\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (find_pool(name)) {
            portal_resp_set_status(resp, PORTAL_CONFLICT);
            n = snprintf(buf, sizeof(buf), "Pool '%s' already exists\n", name);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        pthread_mutex_lock(&g_global_lock);
        if (g_pool_count >= g_max_pools) {
            pthread_mutex_unlock(&g_global_lock);
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            n = snprintf(buf, sizeof(buf), "Max pools reached\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        worker_pool_t *pool = &g_pools[g_pool_count++];
        pthread_mutex_unlock(&g_global_lock);

        snprintf(pool->name, sizeof(pool->name), "%s", name);
        pool->thread_count = thr_s ? atoi(thr_s) : g_default_threads;
        if (pool->thread_count < 1) pool->thread_count = 1;
        if (pool->thread_count > 64) pool->thread_count = 64;
        pool->head = pool->tail = NULL;
        pool->pending = 0;
        pool->total_submitted = 0;
        pool->total_completed = 0;
        pool->total_failed = 0;
        pool->active = 1;
        pool->shutdown = 0;
        pthread_mutex_init(&pool->lock, NULL);
        pthread_cond_init(&pool->cond, NULL);

        pool->threads = calloc((size_t)pool->thread_count, sizeof(pthread_t));
        for (int t = 0; t < pool->thread_count; t++)
            pthread_create(&pool->threads[t], NULL, worker_thread, pool);

        core->event_emit(core, "/events/worker/create", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_CREATED);
        n = snprintf(buf, sizeof(buf), "Pool '%s' created (%d threads)\n",
                     name, pool->thread_count);
        portal_resp_set_body(resp, buf, (size_t)n);
        core->log(core, PORTAL_LOG_INFO, "worker",
                  "Created pool '%s' with %d threads", name, pool->thread_count);
        return 0;
    }

    if (strcmp(msg->path, "/worker/functions/submit") == 0) {
        const char *pool_name = get_hdr(msg, "pool");
        const char *path = get_hdr(msg, "path");
        if (!pool_name || !path) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: pool, path headers\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        worker_pool_t *pool = find_pool(pool_name);
        if (!pool) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            n = snprintf(buf, sizeof(buf), "Pool '%s' not found\n", pool_name);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        worker_job_t *job = calloc(1, sizeof(*job));
        pthread_mutex_lock(&g_global_lock);
        job->id = ++g_job_id;
        pthread_mutex_unlock(&g_global_lock);
        snprintf(job->path, sizeof(job->path), "%s", path);
        job->status = JOB_PENDING;
        job->submitted = (int64_t)time(NULL);
        job->next = NULL;

        pthread_mutex_lock(&pool->lock);
        if (pool->tail) pool->tail->next = job; else pool->head = job;
        pool->tail = job;
        pool->pending++;
        pool->total_submitted++;
        pthread_cond_signal(&pool->cond);
        pthread_mutex_unlock(&pool->lock);

        core->event_emit(core, "/events/worker/submit", path, strlen(path));
        portal_resp_set_status(resp, PORTAL_ACCEPTED);
        n = snprintf(buf, sizeof(buf), "Job #%d submitted to pool '%s'\n",
                     job->id, pool_name);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/worker/functions/destroy") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        worker_pool_t *pool = find_pool(name);
        if (!pool) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            return -1;
        }

        pthread_mutex_lock(&pool->lock);
        pool->shutdown = 1;
        pthread_cond_broadcast(&pool->cond);
        pthread_mutex_unlock(&pool->lock);

        for (int t = 0; t < pool->thread_count; t++)
            pthread_join(pool->threads[t], NULL);

        worker_job_t *j = pool->head;
        while (j) { worker_job_t *nx = j->next; free(j); j = nx; }
        free(pool->threads);
        pthread_mutex_destroy(&pool->lock);
        pthread_cond_destroy(&pool->cond);
        pool->active = 0;

        core->event_emit(core, "/events/worker/destroy", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Pool '%s' destroyed\n", name);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
