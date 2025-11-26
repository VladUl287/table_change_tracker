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

PG_MODULE_MAGIC;

typedef struct
{
    dshash_table_handle table_handle;
    dsa_handle area_handle;
} handlers_t;

typedef struct
{
    char key[NAMEDATALEN];
    TimestampTz timestamp;
} tracker_data;

static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static handlers_t *handlers = NULL;

static uint32 table_name_hash(const void *key, size_t size, void *arg);
static int table_name_compare(const void *a, const void *b, size_t size, void *arg);
static size_t dshash_count(dshash_table *ht);

static dshash_parameters dshash_params = {
    .key_size = NAMEDATALEN,
    .entry_size = sizeof(tracker_data),
    .hash_function = table_name_hash,
    .compare_function = table_name_compare,
};

void _PG_init(void);
void _PG_fini(void);

PG_FUNCTION_INFO_V1(get_last_timestamp);
PG_FUNCTION_INFO_V1(dump_hash_table);
PG_FUNCTION_INFO_V1(enable_table_tracking);
PG_FUNCTION_INFO_V1(disable_table_tracking);

static uint32 table_name_hash(const void *key, size_t size, void *arg)
{
    const char *table_name = (const char *)key;
    return hash_any((const unsigned char *)table_name, strlen(table_name));
}

static int table_name_compare(const void *a, const void *b, size_t size, void *arg)
{
    const char *name1 = (const char *)a;
    const char *name2 = (const char *)b;
    return strncmp(name1, name2, NAMEDATALEN);
}

static size_t dshash_count(dshash_table *ht)
{
    dshash_seq_status status;
    void *entry;
    size_t count = 0;

    dshash_seq_init(&status, ht, false);

    while ((entry = dshash_seq_next(&status)) != NULL)
        count++;

    dshash_seq_term(&status);
    return count;
}

Datum dump_hash_table(PG_FUNCTION_ARGS)
{
    dshash_seq_status status;
    void *entry;
    size_t count = 0;
    dsa_area *seg;
    dshash_table *table;

    seg = dsa_attach(handlers->area_handle);
    table = dshash_attach(seg, &dshash_params, handlers->table_handle, NULL);

    dshash_seq_init(&status, table, false);

    while ((entry = dshash_seq_next(&status)) != NULL)
    {
        tracker_data *data = entry;
        ereport(NOTICE, (errmsg("dshash_get_num_entries returned: %s", data->key)));
    }

    dshash_seq_term(&status);

    dshash_detach(table);
    dsa_detach(seg);

    PG_RETURN_VOID();
}

Datum enable_table_tracking(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL(false);
}

Datum disable_table_tracking(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL(false);
}

Datum get_last_timestamp(PG_FUNCTION_ARGS)
{
    TimestampTz timestamp;
    text *table_name;
    char *table_str;
    bool found;
    char key[NAMEDATALEN];
    dshash_table *table;
    dsa_area *seg;
    tracker_data *entry;

    table_name = PG_GETARG_TEXT_P(0);
    table_str = text_to_cstring(table_name);

    memset(key, 0, NAMEDATALEN);
    strncpy(key, table_str, NAMEDATALEN - 1);

    seg = dsa_attach(handlers->area_handle);
    table = dshash_attach(seg, &dshash_params, handlers->table_handle, NULL);

    entry = dshash_find_or_insert(table, key, &found);
    if (!found)
        entry->timestamp = GetCurrentTimestamp();
    timestamp = entry->timestamp;

    dshash_release_lock(table, entry);

    pfree(table_str);

    dshash_detach(table);
    dsa_detach(seg);

    PG_RETURN_TIMESTAMP(timestamp);
}

static void create_hash_table(void)
{
    bool found;
    dsa_area *seg;
    dshash_table *table;
    dsa_handle area_handle;
    dshash_table_handle table_handle;

    handlers = (handlers_t *)ShmemInitStruct("handlers_t", sizeof(handlers_t), &found);
    if (found)
        return;

    seg = dsa_create(0);
    area_handle = dsa_get_handle(seg);

    table = dshash_create(seg, &dshash_params, NULL);
    table_handle = dshash_get_hash_table_handle(table);

    dsa_pin(seg);
    dsa_detach(seg);
    dshash_detach(table);

    handlers->area_handle = area_handle;
    handlers->table_handle = table_handle;
}

static void track_executor_start(QueryDesc *queryDesc, int eflags)
{
    CmdType operation = queryDesc->operation;
    EState *estate;
    dsa_area *seg;
    dshash_table *table;
    tracker_data *entry;
    char key[NAMEDATALEN];

    if (operation == CMD_INSERT || operation == CMD_UPDATE || operation == CMD_DELETE)
    {
        if (queryDesc->plannedstmt != NULL && queryDesc->plannedstmt->rtable != NIL)
        {
            ListCell *lc;
            foreach (lc, queryDesc->plannedstmt->rtable)
            {
                RangeTblEntry *rte = (RangeTblEntry *)lfirst(lc);

                if (rte->rtekind == RTE_RELATION)
                {
                    char *table_name = get_rel_name(rte->relid);

                    memset(key, 0, NAMEDATALEN);
                    strncpy(key, table_name, NAMEDATALEN - 1);

                    seg = dsa_attach(handlers->area_handle);
                    table = dshash_attach(seg, &dshash_params, handlers->table_handle, NULL);

                    entry = dshash_find(table, key, true);
                    if (entry)
                    {
                        memset(entry->key, 0, NAMEDATALEN);
                        strncpy(entry->key, table_name, NAMEDATALEN - 1);
                        entry->timestamp = GetCurrentTimestamp();
                        dshash_release_lock(table, entry);
                    }

                    dshash_detach(table);
                    dsa_detach(seg);
                    break;
                }
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
    create_hash_table();

    prev_ExecutorStart = ExecutorStart_hook;
    ExecutorStart_hook = track_executor_start;
}

void _PG_fini(void)
{
    ExecutorStart_hook = prev_ExecutorStart;
}