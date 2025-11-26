#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "tcop/utility.h"
#include "executor/executor.h"
#include "storage/shmem.h"
#include "lib/dshash.h"
#include "access/hash.h"
#include "utils/timestamp.h"
#include "utils/lsyscache.h"
#include "access/tableam.h"
#include "utils/memutils.h"
#include "catalog/namespace.h"

PG_MODULE_MAGIC;

#define LWTRANCHE_APP 1

typedef struct
{
    bool enabled;
    size_t max_table_name_len;
} tracker_config_t;

typedef struct
{
    dshash_table_handle table_handle;
    dsa_handle area_handle;
    bool initialized;
} handlers_t;

typedef struct
{
    char key[NAMEDATALEN];
    Oid oid;
    TimestampTz timestamp;
} tracker_data_t;

static void tracker_init(void);
static void tracker_shutdown(void);
static bool tracker_ensure_initialized(void);
static bool tracker_validate_table_name(const char *table_name);
static void tracker_copy_table_name(char *dest, const char *src);
static dsa_area *tracker_attach_dsa(void);
static dshash_table *tracker_attach_hash_table(dsa_area *seg);
static void tracker_detach_all(dshash_table *table, dsa_area *seg);
static uint32 table_name_hash(const void *key, size_t size, void *arg);
static int table_name_compare(const void *a, const void *b, size_t size, void *arg);

static ExecutorStart_hook_type prev_ExecutorStart = NULL;

static handlers_t *handlers = NULL;
static tracker_config_t config = {
    .enabled = true,
    .max_table_name_len = NAMEDATALEN - 1,
};

static const dshash_parameters dshash_params = {
    .key_size = NAMEDATALEN,
    .entry_size = sizeof(tracker_data_t),
    .hash_function = table_name_hash,
    .compare_function = table_name_compare,
};

PG_FUNCTION_INFO_V1(get_last_timestamp);
PG_FUNCTION_INFO_V1(enable_table_tracking);
PG_FUNCTION_INFO_V1(disable_table_tracking);
PG_FUNCTION_INFO_V1(is_table_tracked);

static uint32 table_name_hash(const void *key, size_t size, void *arg)
{
    const char *table_name = (const char *)key;
    return hash_any((const unsigned char *)table_name, strnlen(table_name, NAMEDATALEN));
}

static int table_name_compare(const void *a, const void *b, size_t size, void *arg)
{
    const char *name1 = (const char *)a;
    const char *name2 = (const char *)b;
    return strncmp(name1, name2, NAMEDATALEN);
}

static void tracker_init(void)
{
    bool found;
    dsa_area *seg = NULL;
    dshash_table *table = NULL;

    handlers = (handlers_t *)ShmemInitStruct("table_tracker_handlers", sizeof(handlers_t), &found);

    if (found && handlers->initialized)
        return;

    memset(handlers, 0, sizeof(handlers_t));

    seg = dsa_create(LWTRANCHE_APP);
    if (!seg)
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("could not create dynamic shared area")));

    table = dshash_create(seg, &dshash_params, NULL);
    if (!table)
    {
        dsa_detach(seg);
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("could not create hash table")));
    }

    handlers->area_handle = dsa_get_handle(seg);
    handlers->table_handle = dshash_get_hash_table_handle(table);
    handlers->initialized = true;

    dsa_pin(seg);
    dsa_pin_mapping(seg);

    tracker_detach_all(table, seg);
}

static void tracker_shutdown(void)
{
    if (handlers && handlers->initialized)
    {
        dsa_area *seg = tracker_attach_dsa();
        if (seg)
        {
            dsa_unpin(seg);
            dsa_detach(seg);
        }
        handlers->initialized = false;
    }
}

static bool tracker_ensure_initialized(void)
{
    if (!handlers || !handlers->initialized)
    {
        ereport(WARNING, (errmsg("table tracker not initialized")));
        return false;
    }
    return true;
}

static bool tracker_validate_table_name(const char *table_name)
{
    if (!table_name || strlen(table_name) == 0)
    {
        ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("table name cannot be null or empty")));
        return false;
    }

    if (strlen(table_name) >= NAMEDATALEN)
    {
        ereport(ERROR,
                (errcode(ERRCODE_NAME_TOO_LONG),
                 errmsg("table name too long: %s", table_name),
                 errdetail("Maximum length is %ld characters", config.max_table_name_len)));
        return false;
    }

    return true;
}

static void tracker_copy_table_name(char *dest, const char *src)
{
    memset(dest, 0, NAMEDATALEN);
    strncpy(dest, src, config.max_table_name_len);
}

static dsa_area *tracker_attach_dsa(void)
{
    dsa_area *seg;

    if (!tracker_ensure_initialized())
        return NULL;

    seg = dsa_attach(handlers->area_handle);
    if (!seg)
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("could not attach to dynamic shared area")));

    return seg;
}

static dshash_table *tracker_attach_hash_table(dsa_area *seg)
{
    dshash_table *table = dshash_attach(seg, &dshash_params,
                                        handlers->table_handle, NULL);
    if (!table)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("could not attach to hash table")));

    return table;
}

static void tracker_detach_all(dshash_table *table, dsa_area *seg)
{
    if (table)
        dshash_detach(table);
    if (seg)
        dsa_detach(seg);
}

Datum is_table_tracked(PG_FUNCTION_ARGS)
{
    text *table_name;
    char *table_str;
    char key[NAMEDATALEN];
    dsa_area *seg = NULL;
    dshash_table *table = NULL;
    tracker_data_t *entry;
    bool found = false;

    if (PG_ARGISNULL(0))
        PG_RETURN_BOOL(false);

    if (!tracker_ensure_initialized())
        PG_RETURN_BOOL(false);

    table_name = PG_GETARG_TEXT_P(0);
    table_str = text_to_cstring(table_name);

    if (!tracker_validate_table_name(table_str))
        PG_RETURN_BOOL(false);

    tracker_copy_table_name(key, table_str);

    seg = tracker_attach_dsa();
    table = tracker_attach_hash_table(seg);

    entry = dshash_find(table, key, false);
    found = (entry != NULL);

    if (found)
        dshash_release_lock(table, entry);

    tracker_detach_all(table, seg);
    pfree(table_str);

    PG_RETURN_BOOL(found);
}

Datum enable_table_tracking(PG_FUNCTION_ARGS)
{
    text *table_name;
    char *table_str;
    char key[NAMEDATALEN];
    dsa_area *seg = NULL;
    dshash_table *table = NULL;
    tracker_data_t *entry;
    bool found;
    Oid relation_oid = InvalidOid;

    if (PG_ARGISNULL(0))
        ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("table name cannot be null")));

    if (!tracker_ensure_initialized())
        PG_RETURN_BOOL(false);

    table_name = PG_GETARG_TEXT_P(0);
    table_str = text_to_cstring(table_name);

    if (!tracker_validate_table_name(table_str))
        PG_RETURN_BOOL(false);

    relation_oid = RelnameGetRelid(table_str);
    if (!OidIsValid(relation_oid))
        ereport(WARNING, (errmsg("table '%s' does not exist or cannot be accessed", table_str)));

    tracker_copy_table_name(key, table_str);

    seg = tracker_attach_dsa();
    table = tracker_attach_hash_table(seg);

    entry = dshash_find_or_insert(table, key, &found);
    if (!entry)
    {
        tracker_detach_all(table, seg);
        pfree(table_str);
        PG_RETURN_BOOL(false);
    }

    if (!found)
    {
        tracker_copy_table_name(entry->key, table_str);
        entry->oid = relation_oid;
    }

    entry->timestamp = GetCurrentTimestamp();

    dshash_release_lock(table, entry);
    tracker_detach_all(table, seg);
    pfree(table_str);

    PG_RETURN_BOOL(true);
}

Datum disable_table_tracking(PG_FUNCTION_ARGS)
{
    text *table_name;
    char *table_str;
    char key[NAMEDATALEN];
    dsa_area *seg = NULL;
    dshash_table *table = NULL;
    bool result = false;

    if (PG_ARGISNULL(0))
        ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("table name cannot be null")));

    if (!tracker_ensure_initialized())
        PG_RETURN_BOOL(false);

    table_name = PG_GETARG_TEXT_P(0);
    table_str = text_to_cstring(table_name);

    if (!tracker_validate_table_name(table_str))
        PG_RETURN_BOOL(false);

    tracker_copy_table_name(key, table_str);

    seg = tracker_attach_dsa();
    table = tracker_attach_hash_table(seg);

    result = dshash_delete_key(table, key);

    tracker_detach_all(table, seg);
    pfree(table_str);

    PG_RETURN_BOOL(result);
}

Datum get_last_timestamp(PG_FUNCTION_ARGS)
{
    TimestampTz timestamp = 0;
    text *table_name;
    char *table_str;
    char key[NAMEDATALEN];
    dsa_area *seg = NULL;
    dshash_table *table = NULL;
    tracker_data_t *entry;

    if (PG_ARGISNULL(0))
        PG_RETURN_NULL();

    if (!tracker_ensure_initialized())
        PG_RETURN_NULL();

    table_name = PG_GETARG_TEXT_P(0);
    table_str = text_to_cstring(table_name);

    if (!tracker_validate_table_name(table_str))
        PG_RETURN_NULL();

    tracker_copy_table_name(key, table_str);

    seg = tracker_attach_dsa();
    table = tracker_attach_hash_table(seg);

    entry = dshash_find(table, key, false);
    if (!entry)
    {
        tracker_detach_all(table, seg);
        pfree(table_str);
        PG_RETURN_NULL();
    }

    timestamp = entry->timestamp;
    dshash_release_lock(table, entry);

    tracker_detach_all(table, seg);
    pfree(table_str);

    PG_RETURN_TIMESTAMP(timestamp);
}

static void track_executor_start(QueryDesc *queryDesc, int eflags)
{
    CmdType operation = queryDesc->operation;

    if ((operation == CMD_INSERT || operation == CMD_UPDATE || operation == CMD_DELETE) &&
        (queryDesc->plannedstmt && queryDesc->plannedstmt->rtable))
    {
        ListCell *lc;
        foreach (lc, queryDesc->plannedstmt->rtable)
        {
            RangeTblEntry *rte = (RangeTblEntry *)lfirst(lc);

            if (rte->rtekind == RTE_RELATION)
            {
                char *table_name = get_rel_name(rte->relid);
                if (table_name)
                {
                    char key[NAMEDATALEN];
                    dsa_area *seg = NULL;
                    dshash_table *table = NULL;
                    tracker_data_t *entry;

                    if (!tracker_ensure_initialized())
                        break;

                    tracker_copy_table_name(key, table_name);

                    seg = tracker_attach_dsa();
                    table = tracker_attach_hash_table(seg);

                    entry = dshash_find(table, key, true);
                    if (entry)
                    {
                        entry->timestamp = GetCurrentTimestamp();
                        entry->oid = rte->relid;
                        dshash_release_lock(table, entry);
                    }

                    tracker_detach_all(table, seg);
                }
                break;
            }
        }
    }

    if (prev_ExecutorStart)
        prev_ExecutorStart(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);
}

void _PG_init(void)
{
    tracker_init();

    prev_ExecutorStart = ExecutorStart_hook;
    ExecutorStart_hook = track_executor_start;

    ereport(LOG, (errmsg("Table tracker extension initialized")));
}

void _PG_fini(void)
{
    ExecutorStart_hook = prev_ExecutorStart;

    tracker_shutdown();

    ereport(LOG, (errmsg("Table tracker extension cleaned up")));
}