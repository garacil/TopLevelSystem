/*
 * module.h — Module interface definition
 *
 * Defines the 4 symbols every .so module must export:
 * portal_module_info, portal_module_load, portal_module_unload, portal_module_handle
 */

#ifndef PORTAL_MODULE_H
#define PORTAL_MODULE_H

#include <stdint.h>
#include "core.h"

/* Module descriptor — returned by portal_module_info() */
typedef struct {
    const char  *name;
    const char  *version;
    const char  *description;
    const char **soft_deps;     /* NULL-terminated array, or NULL if none */
} portal_module_info_t;

/*
 * Every module shared library (.so/.dll) must export these 4 symbols:
 *
 *   portal_module_info_t *portal_module_info(void);
 *   int  portal_module_load(portal_core_t *core);
 *   int  portal_module_unload(portal_core_t *core);
 *   int  portal_module_handle(portal_core_t *core,
 *                             const portal_msg_t *msg,
 *                             portal_resp_t *resp);
 */

typedef portal_module_info_t *(*portal_module_info_fn)(void);
typedef int  (*portal_module_load_fn)(portal_core_t *core);
typedef int  (*portal_module_unload_fn)(portal_core_t *core);
typedef int  (*portal_module_handle_fn)(portal_core_t *core,
                                        const portal_msg_t *msg,
                                        portal_resp_t *resp);

/* Internal: loaded module record (used by core_module.c) */
typedef struct {
    char                       name[PORTAL_MAX_MODULE_NAME];
    void                      *handle;      /* dlopen handle */
    portal_module_info_fn      fn_info;
    portal_module_load_fn      fn_load;
    portal_module_unload_fn    fn_unload;
    portal_module_handle_fn    fn_handle;
    portal_module_info_t      *info;
    int                        loaded;      /* 1 = active */
    volatile int               use_count;   /* active calls — must be 0 to unload */
    int                        unloading;   /* 1 = pending unload, reject new calls */
    /* Observability counters (incremented in core dispatch) */
    uint64_t                   msg_count;   /* total messages handled */
    uint64_t                   last_msg_us; /* monotonic timestamp of last call */
} portal_module_entry_t;

#endif /* PORTAL_MODULE_H */
