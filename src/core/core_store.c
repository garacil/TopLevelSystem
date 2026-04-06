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
 * core_store.c — File-based persistent storage
 *
 * Manages /etc/portal/<instance>/users/, groups/, modules/ directories.
 * One INI file per entity. Atomic writes via rename. Always-available
 * fallback when no database backend is loaded.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include "core_store.h"
#include "core_log.h"

static int ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
        return 0;
    if (mkdir(path, 0755) == 0) {
        LOG_INFO("store", "Created directory: %s", path);
        return 0;
    }
    return -1;
}

int portal_store_init(portal_store_t *store, const char *base_dir)
{
    snprintf(store->base_dir, sizeof(store->base_dir), "%s", base_dir);

    /* Create subdirectories */
    char path[PORTAL_MAX_PATH_LEN];
    ensure_dir(base_dir);
    snprintf(path, sizeof(path), "%s/users", base_dir);
    ensure_dir(path);
    snprintf(path, sizeof(path), "%s/groups", base_dir);
    ensure_dir(path);
    snprintf(path, sizeof(path), "%s/modules", base_dir);
    ensure_dir(path);

    LOG_INFO("store", "Storage initialized at %s", base_dir);
    return 0;
}

/* --- Helpers --- */

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

void portal_store_path(const portal_store_t *store, const char *subdir,
                        const char *name, char *out, size_t out_len)
{
    snprintf(out, out_len, "%s/%s/%s.conf", store->base_dir, subdir, name);
}

int portal_store_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

int portal_store_delete(const char *path)
{
    return unlink(path);
}

/* --- INI read/write --- */

int portal_store_read_ini(const char *path, portal_ht_t *kv)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        if (*s == '\0' || *s == '#' || *s == ';') continue;

        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';

        char *key = trim(s);
        char *val = trim(eq + 1);
        portal_ht_set(kv, key, strdup(val));
    }

    fclose(f);
    return 0;
}

typedef struct {
    FILE *f;
} write_ctx_t;

static void write_kv_cb(const char *key, void *value, void *userdata)
{
    write_ctx_t *ctx = userdata;
    fprintf(ctx->f, "%s = %s\n", key, (const char *)value);
}

int portal_store_write_ini(const char *path, portal_ht_t *kv)
{
    /* Write to temp file, then rename (atomic) */
    char tmp[PORTAL_MAX_PATH_LEN];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    FILE *f = fopen(tmp, "w");
    if (!f) return -1;

    fprintf(f, "# Portal auto-generated config\n");
    write_ctx_t ctx = { .f = f };
    portal_ht_iter(kv, write_kv_cb, &ctx);

    fclose(f);
    return rename(tmp, path);
}

char *portal_store_read_value(const char *path, const char *key)
{
    portal_ht_t kv;
    portal_ht_init(&kv, 16);

    if (portal_store_read_ini(path, &kv) < 0) {
        portal_ht_destroy(&kv);
        return NULL;
    }

    char *val = portal_ht_get(&kv, key);
    char *result = val ? strdup(val) : NULL;

    /* Free all strdup'd values */
    portal_ht_destroy(&kv);
    return result;
}

int portal_store_write_value(const char *path, const char *key, const char *value)
{
    portal_ht_t kv;
    portal_ht_init(&kv, 16);

    /* Load existing */
    portal_store_read_ini(path, &kv);

    /* Update/add */
    /* Free old value if exists */
    char *old = portal_ht_get(&kv, key);
    if (old) free(old);
    portal_ht_set(&kv, key, strdup(value));

    int rc = portal_store_write_ini(path, &kv);

    /* Cleanup */
    portal_ht_destroy(&kv);
    return rc;
}

/* --- Directory listing --- */

int portal_store_list_dir(const char *dir_path, portal_store_list_fn cb,
                           void *userdata)
{
    DIR *d = opendir(dir_path);
    if (!d) return -1;

    struct dirent *entry;
    int count = 0;

    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        /* Strip .conf extension */
        char name[256];
        snprintf(name, sizeof(name), "%s", entry->d_name);
        char *dot = strstr(name, ".conf");
        if (dot) *dot = '\0';
        else continue;  /* skip non-.conf files */

        cb(name, userdata);
        count++;
    }

    closedir(d);
    return count;
}
