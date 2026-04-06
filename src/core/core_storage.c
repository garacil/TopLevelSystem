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
 * core_storage.c — Multi-provider storage registry
 *
 * Manages multiple storage backends (file, psql, sqlite).
 * All providers receive writes. Core uses first successful read.
 * Providers register via core->storage_register().
 */

#include <string.h>
#include "portal/storage.h"
#include "core_log.h"

void portal_storage_init(portal_storage_registry_t *reg)
{
    memset(reg, 0, sizeof(*reg));
}

int portal_storage_add(portal_storage_registry_t *reg,
                        portal_storage_provider_t *provider)
{
    if (!provider || reg->count >= STORAGE_MAX_PROVIDERS)
        return -1;

    /* Check duplicate */
    for (int i = 0; i < reg->count; i++)
        if (strcmp(reg->providers[i]->name, provider->name) == 0)
            return -1;

    reg->providers[reg->count++] = provider;
    LOG_INFO("storage", "Provider '%s' registered (%d active)",
             provider->name, reg->count);
    return 0;
}

int portal_storage_remove(portal_storage_registry_t *reg, const char *name)
{
    for (int i = 0; i < reg->count; i++) {
        if (strcmp(reg->providers[i]->name, name) == 0) {
            /* Shift remaining */
            for (int j = i; j < reg->count - 1; j++)
                reg->providers[j] = reg->providers[j + 1];
            reg->count--;
            LOG_INFO("storage", "Provider '%s' removed (%d active)",
                     name, reg->count);
            return 0;
        }
    }
    return -1;
}

portal_storage_provider_t *portal_storage_find(portal_storage_registry_t *reg,
                                                const char *name)
{
    for (int i = 0; i < reg->count; i++)
        if (strcmp(reg->providers[i]->name, name) == 0)
            return reg->providers[i];
    return NULL;
}

void portal_storage_save_user(portal_storage_registry_t *reg,
                               const char *username, const char *password,
                               const char *api_key, const char *groups)
{
    for (int i = 0; i < reg->count; i++) {
        if (reg->providers[i]->user_save)
            reg->providers[i]->user_save(reg->providers[i]->ctx,
                username, password, api_key, groups);
    }
}

void portal_storage_save_group(portal_storage_registry_t *reg,
                                const char *name, const char *description,
                                const char *created_by)
{
    for (int i = 0; i < reg->count; i++) {
        if (reg->providers[i]->group_save)
            reg->providers[i]->group_save(reg->providers[i]->ctx,
                name, description, created_by);
    }
}

void portal_storage_save_config(portal_storage_registry_t *reg,
                                 const char *module, const char *key,
                                 const char *value)
{
    for (int i = 0; i < reg->count; i++) {
        if (reg->providers[i]->config_set)
            reg->providers[i]->config_set(reg->providers[i]->ctx,
                module, key, value);
    }
}

int portal_storage_get_config(portal_storage_registry_t *reg,
                               const char *module, const char *key,
                               char *value, size_t val_len)
{
    for (int i = 0; i < reg->count; i++) {
        if (reg->providers[i]->config_get &&
            reg->providers[i]->config_get(reg->providers[i]->ctx,
                module, key, value, val_len) == 0)
            return 0;
    }
    return -1;
}
