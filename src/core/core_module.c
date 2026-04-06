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
 * core_module.c — Module lifecycle management
 *
 * Loads .so modules via dlopen, resolves 4 required symbols,
 * manages load/unload/reload with reference counting for
 * safe unload during active message processing.
 */

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "core_module.h"
#include "core_log.h"

void portal_module_registry_init(portal_module_registry_t *reg, const char *modules_dir)
{
    memset(reg, 0, sizeof(*reg));
    snprintf(reg->modules_dir, sizeof(reg->modules_dir), "%s", modules_dir);
}

void portal_module_registry_destroy(portal_module_registry_t *reg, portal_core_t *core)
{
    /* Unload in reverse order */
    for (int i = reg->count - 1; i >= 0; i--) {
        if (reg->entries[i].loaded) {
            LOG_INFO("module", "Unloading module '%s'", reg->entries[i].name);
            if (reg->entries[i].fn_unload)
                reg->entries[i].fn_unload(core);
            if (reg->entries[i].handle)
                dlclose(reg->entries[i].handle);
            reg->entries[i].loaded = 0;
        }
    }
    reg->count = 0;
}

portal_module_entry_t *portal_module_find(portal_module_registry_t *reg,
                                           const char *name)
{
    /* Prefer loaded entry, fall back to any entry with this name */
    portal_module_entry_t *fallback = NULL;
    for (int i = 0; i < reg->count; i++) {
        if (strcmp(reg->entries[i].name, name) == 0) {
            if (reg->entries[i].loaded)
                return &reg->entries[i];
            if (!fallback)
                fallback = &reg->entries[i];
        }
    }
    return fallback;
}

int portal_module_is_loaded(portal_module_registry_t *reg, const char *name)
{
    portal_module_entry_t *e = portal_module_find(reg, name);
    return (e && e->loaded) ? 1 : 0;
}

int portal_module_do_load(portal_module_registry_t *reg, const char *name,
                           portal_core_t *core)
{
    if (reg->count >= PORTAL_MAX_MODULES) {
        LOG_ERROR("module", "Module limit reached (%d)", PORTAL_MAX_MODULES);
        return -1;
    }

    if (portal_module_is_loaded(reg, name)) {
        LOG_WARN("module", "Module '%s' already loaded", name);
        return -1;
    }

    /* Build path: modules_dir/mod_<name>.so */
    char path[PORTAL_MAX_PATH_LEN + PORTAL_MAX_MODULE_NAME + 16];
    snprintf(path, sizeof(path), "%s/mod_%s.so", reg->modules_dir, name);

    void *handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        LOG_ERROR("module", "Failed to load '%s': %s", path, dlerror());
        return -1;
    }

    /* Resolve symbols */
    portal_module_info_fn fn_info =
        (portal_module_info_fn)dlsym(handle, "portal_module_info");
    portal_module_load_fn fn_load =
        (portal_module_load_fn)dlsym(handle, "portal_module_load");
    portal_module_unload_fn fn_unload =
        (portal_module_unload_fn)dlsym(handle, "portal_module_unload");
    portal_module_handle_fn fn_handle =
        (portal_module_handle_fn)dlsym(handle, "portal_module_handle");

    if (!fn_info || !fn_load || !fn_unload || !fn_handle) {
        LOG_ERROR("module", "Module '%s' missing required symbols", name);
        dlclose(handle);
        return -1;
    }

    portal_module_info_t *info = fn_info();
    if (!info || !info->name) {
        LOG_ERROR("module", "Module '%s' returned invalid info", name);
        dlclose(handle);
        return -1;
    }

    /* Call module load */
    if (fn_load(core) != PORTAL_MODULE_OK) {
        LOG_ERROR("module", "Module '%s' load() failed", name);
        dlclose(handle);
        return -1;
    }

    /* Law 9: Module authentication — identify which user this module runs as */
    const char *mod_user = core->config_get(core, name, "user");
    const char *mod_key  = core->config_get(core, name, "key");
    if (mod_user && mod_key && mod_key[0]) {
        /* Authenticate module with its own credentials */
        portal_msg_t *auth_msg = portal_msg_alloc();
        portal_resp_t *auth_resp = portal_resp_alloc();
        if (auth_msg && auth_resp) {
            portal_msg_set_path(auth_msg, "/auth/login");
            portal_msg_set_method(auth_msg, PORTAL_METHOD_CALL);
            portal_msg_add_header(auth_msg, "username", mod_user);
            portal_msg_add_header(auth_msg, "api_key", mod_key);
            core->send(core, auth_msg, auth_resp);
            if (auth_resp->status == PORTAL_OK)
                LOG_INFO("module", "Module '%s' authenticated as '%s'",
                         name, mod_user);
            else
                LOG_WARN("module", "Module '%s' auth failed as '%s' (running as root)",
                         name, mod_user);
            portal_msg_free(auth_msg);
            portal_resp_free(auth_resp);
        }
    } else {
        LOG_DEBUG("module", "Module '%s' running as root (no credentials configured)",
                  name);
    }

    /* Register — reuse existing slot if available */
    portal_module_entry_t *entry = portal_module_find(reg, name);
    if (!entry)
        entry = &reg->entries[reg->count++];
    snprintf(entry->name, sizeof(entry->name), "%s", name);
    entry->handle = handle;
    entry->fn_info = fn_info;
    entry->fn_load = fn_load;
    entry->fn_unload = fn_unload;
    entry->fn_handle = fn_handle;
    entry->info = info;
    entry->loaded = 1;

    LOG_INFO("module", "Loaded module '%s' v%s — %s",
             info->name, info->version, info->description);
    return 0;
}

int portal_module_do_unload(portal_module_registry_t *reg, const char *name,
                             portal_core_t *core)
{
    portal_module_entry_t *entry = portal_module_find(reg, name);
    if (!entry || !entry->loaded) {
        LOG_WARN("module", "Module '%s' not loaded", name);
        return -1;
    }

    /* Mark as unloading — reject new calls */
    entry->unloading = 1;

    /* Wait for active calls to finish (bounded wait) */
    int max_wait = 50;  /* 50 * 10ms = 500ms max */
    while (entry->use_count > 0 && max_wait-- > 0) {
        struct timespec ts = {0, 10000000};  /* 10ms */
        nanosleep(&ts, NULL);
    }

    if (entry->use_count > 0) {
        LOG_WARN("module", "Module '%s' still has %d active calls, forcing unload",
                 name, entry->use_count);
    }

    LOG_INFO("module", "Unloading module '%s'", name);

    if (entry->fn_unload)
        entry->fn_unload(core);

    if (entry->handle)
        dlclose(entry->handle);

    entry->loaded = 0;
    entry->unloading = 0;
    entry->use_count = 0;
    entry->handle = NULL;
    return 0;
}

int portal_module_do_reload(portal_module_registry_t *reg, const char *name,
                             portal_core_t *core)
{
    LOG_INFO("module", "Reloading module '%s'", name);

    if (portal_module_do_unload(reg, name, core) < 0) {
        LOG_ERROR("module", "Reload failed: could not unload '%s'", name);
        return -1;
    }

    if (portal_module_do_load(reg, name, core) < 0) {
        LOG_ERROR("module", "Reload failed: could not load '%s'", name);
        return -1;
    }

    LOG_INFO("module", "Module '%s' reloaded successfully", name);
    return 0;
}
