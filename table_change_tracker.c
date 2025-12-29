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
#include "storage/ipc.h"
#include "miscadmin.h"

#define DSA_TRANCHE_APP 1
#define TABLE_TRACKER_DSA_SIZE sizeof(shared_handlers)
#define TABLE_TRACKER_HANDLERS "table_tracker_handlers"

PG_MODULE_MAGIC;

typedef struct
{
    dshash_table_handle table_handle;
    dsa_handle area_handle;
} shared_handlers;

typedef struct
{
    Oid key;
    TimestampTz timestamp;
} tracker_entity;

static shared_handlers *handlers = NULL;
static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static shmem_request_hook_type prev_shmem_request_hook = NULL;
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;

static void tracker_detach_all(dshash_table *table, dsa_area *seg);
static uint32 oid_key_hash(const void *key, size_t size, void *arg);

static const dshash_parameters dshash_params = {
    .key_size = sizeof(Oid),
    .entry_size = sizeof(tracker_entity),
    .hash_function = oid_key_hash,
    .compare_function = dshash_memcmp,
};

PG_FUNCTION_INFO_V1(get_last_timestamp);
PG_FUNCTION_INFO_V1(enable_table_tracking);
PG_FUNCTION_INFO_V1(disable_table_tracking);
PG_FUNCTION_INFO_V1(is_table_tracked);
PG_FUNCTION_INFO_V1(set_last_timestamp);
PG_FUNCTION_INFO_V1(get_last_timestamps);

static uint32 oid_key_hash(const void *key, size_t size, void *arg)
{
    return oid_hash(key, size);
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
    Oid table_oid = InvalidOid;
    bool found;

    dshash_table *table = NULL;
    tracker_entity *entry;
    dsa_area *seg = NULL;

    if (PG_ARGISNULL(0))
        PG_RETURN_BOOL(false);

    table_oid = PG_GETARG_OID(0);

    seg = dsa_attach(handlers->area_handle);
    table = dshash_attach(seg, &dshash_params, handlers->table_handle, NULL);

    entry = dshash_find(table, &table_oid, false);
    found = (entry != NULL);

    if (found)
        dshash_release_lock(table, entry);

    tracker_detach_all(table, seg);

    PG_RETURN_BOOL(found);
}

Datum enable_table_tracking(PG_FUNCTION_ARGS)
{
    Oid table_oid = InvalidOid;
    bool found;

    dshash_table *table = NULL;
    tracker_entity *entry;
    dsa_area *seg = NULL;

    if (PG_ARGISNULL(0))
        ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("table name cannot be null")));

    table_oid = PG_GETARG_OID(0);

    seg = dsa_attach(handlers->area_handle);
    table = dshash_attach(seg, &dshash_params, handlers->table_handle, NULL);

    entry = dshash_find_or_insert(table, &table_oid, &found);
    if (!entry)
    {
        tracker_detach_all(table, seg);
        PG_RETURN_BOOL(false);
    }

    if (!found)
    {
        entry->key = table_oid;
        entry->timestamp = GetCurrentTimestamp();
    }

    dshash_release_lock(table, entry);
    tracker_detach_all(table, seg);

    PG_RETURN_BOOL(true);
}

Datum disable_table_tracking(PG_FUNCTION_ARGS)
{
    Oid table_oid = InvalidOid;
    bool result;

    dshash_table *table = NULL;
    dsa_area *seg = NULL;

    if (PG_ARGISNULL(0))
        ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("table name cannot be null")));

    table_oid = PG_GETARG_OID(0);

    seg = dsa_attach(handlers->area_handle);
    table = dshash_attach(seg, &dshash_params, handlers->table_handle, NULL);

    result = dshash_delete_key(table, &table_oid);

    tracker_detach_all(table, seg);

    PG_RETURN_BOOL(result);
}

Datum get_last_timestamp(PG_FUNCTION_ARGS)
{
    Oid table_oid = InvalidOid;
    TimestampTz timestamp = 0;

    dsa_area *seg = NULL;
    dshash_table *table = NULL;
    tracker_entity *entry = NULL;

    if (PG_ARGISNULL(0))
        PG_RETURN_NULL();

    table_oid = PG_GETARG_OID(0);

    seg = dsa_attach(handlers->area_handle);
    table = dshash_attach(seg, &dshash_params, handlers->table_handle, NULL);

    entry = dshash_find(table, &table_oid, false);
    if (!entry)
    {
        tracker_detach_all(table, seg);
        PG_RETURN_NULL();
    }

    timestamp = entry->timestamp;
    dshash_release_lock(table, entry);
    tracker_detach_all(table, seg);

    PG_RETURN_TIMESTAMPTZ(timestamp);
}

Datum get_last_timestamps(PG_FUNCTION_ARGS)
{
    ArrayType *input_array;
    Oid *table_oids;
    int num_tables;
    Datum *timestamp_datums;
    ArrayType *result_array;
    bool *nulls;
    dsa_area *seg = NULL;
    dshash_table *table = NULL;
    bool *result_nulls;

    if (PG_ARGISNULL(0))
        PG_RETURN_NULL();

    input_array = PG_GETARG_ARRAYTYPE_P(0);

    deconstruct_array(
        input_array, REGCLASSOID, sizeof(Oid), true, 'i', (Datum **)&table_oids, &nulls, &num_tables);

    timestamp_datums = palloc(sizeof(Datum) * num_tables);
    result_nulls = palloc(sizeof(bool) * num_tables);

    seg = dsa_attach(handlers->area_handle);
    table = dshash_attach(seg, &dshash_params, handlers->table_handle, NULL);

    for (int i = 0; i < num_tables; i++)
    {
        tracker_entity *entry = NULL;

        if (nulls[i])
        {
            result_nulls[i] = true;
            timestamp_datums[i] = (Datum)0;
            continue;
        }

        entry = dshash_find(table, &table_oids[i], false);

        if (!entry)
        {
            result_nulls[i] = true;
            timestamp_datums[i] = (Datum)0;
        }
        else
        {
            timestamp_datums[i] = TimestampTzGetDatum(entry->timestamp);
            result_nulls[i] = false;
            dshash_release_lock(table, entry);
        }
    }

    tracker_detach_all(table, seg);

    result_array = construct_array(
        timestamp_datums, num_tables, TIMESTAMPTZOID, sizeof(TimestampTz), true, 'd');

    PG_RETURN_ARRAYTYPE_P(result_array);
}

Datum set_last_timestamp(PG_FUNCTION_ARGS)
{
    Oid table_oid = InvalidOid;
    TimestampTz last_timestamp;
    bool found = false;

    dsa_area *seg = NULL;
    dshash_table *table = NULL;
    tracker_entity *entry = NULL;

    if (PG_ARGISNULL(0))
        PG_RETURN_BOOL(false);

    table_oid = PG_GETARG_OID(0);
    last_timestamp = PG_GETARG_TIMESTAMPTZ(1);

    seg = dsa_attach(handlers->area_handle);
    table = dshash_attach(seg, &dshash_params, handlers->table_handle, NULL);

    entry = dshash_find(table, &table_oid, true);
    if (entry)
    {
        entry->timestamp = last_timestamp;
        dshash_release_lock(table, entry);
        found = true;
    }

    tracker_detach_all(table, seg);
    PG_RETURN_BOOL(found);
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
                dsa_area *seg = NULL;
                dshash_table *table = NULL;
                tracker_entity *entry;

                seg = dsa_attach(handlers->area_handle);
                table = dshash_attach(seg, &dshash_params, handlers->table_handle, NULL);

                entry = dshash_find(table, &rte->relid, true);
                if (entry)
                {
                    entry->timestamp = GetCurrentTimestamp();
                    dshash_release_lock(table, entry);
                }

                tracker_detach_all(table, seg);
                break;
            }
        }
    }

    if (prev_ExecutorStart)
        prev_ExecutorStart(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);
}

static void tracker_shmem_request(void)
{
    if (prev_shmem_request_hook)
        prev_shmem_request_hook();

    ereport(DEBUG1,
            (errmsg("table tracker: requesting shared memory resources"),
             errdetail("Memory: %zu bytes", TABLE_TRACKER_DSA_SIZE)));

    RequestAddinShmemSpace(sizeof(shared_handlers));

    ereport(DEBUG2,
            (errmsg("table tracker: shared memory request registered"),
             errdetail("Size: %zu bytes", TABLE_TRACKER_DSA_SIZE)));

    ereport(LOG,
            (errmsg("table tracker: memory request phase completed"),
             errcontext("shmem_request_hook execution")));
}

static void tracker_shmem_startup(void)
{
    bool found;
    dsa_area *seg = NULL;
    dshash_table *table = NULL;

    if (prev_shmem_startup_hook)
        prev_shmem_startup_hook();

    ereport(DEBUG1,
            (errmsg("table tracker: starting shared memory initialization"),
             errcontext("shmem_startup_hook execution")));

    LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

    handlers = (shared_handlers *)ShmemInitStruct(
        TABLE_TRACKER_HANDLERS,
        sizeof(shared_handlers),
        &found);

    if (found)
    {
        ereport(DEBUG2,
                (errmsg("table tracker: reusing existing shared memory"),
                 errdetail("Handlers already initialized by another process")));
        LWLockRelease(AddinShmemInitLock);
        return;
    }

    ereport(LOG,
            (errmsg("table tracker: performing first-time initialization"),
             errdetail("Process ID: %d", MyProcPid)));

    memset(handlers, 0, sizeof(shared_handlers));

    ereport(DEBUG2, (errmsg("table tracker: creating DSA")));

    seg = dsa_create(DSA_TRANCHE_APP);
    if (!seg)
    {
        LWLockRelease(AddinShmemInitLock);
        ereport(ERROR,
                (errcode(ERRCODE_OUT_OF_MEMORY),
                 errmsg("table tracker: failed to create Dynamic Shared Area"),
                 errdetail("DSA creation failed. System may be out of shared memory."),
                 errhint("Increase max_dsa_size or reduce other shared memory usage."),
                 errcontext("DSA initialization phase")));
        return;
    }

    ereport(DEBUG2, (errmsg("table tracker: creating hash table")));

    table = dshash_create(seg, &dshash_params, NULL);
    if (!table)
    {
        tracker_detach_all(table, seg);
        LWLockRelease(AddinShmemInitLock);
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_RESOURCES),
                 errmsg("table tracker: failed to create distributed hash table"),
                 errdetail("Hash table creation within DSA failed"),
                 errhint("DSA might be fragmented. Consider increasing max_dsa_size."),
                 errcontext("Hash table initialization phase")));
        return;
    }

    handlers->area_handle = dsa_get_handle(seg);
    if (handlers->area_handle == DSA_HANDLE_INVALID)
    {
        LWLockRelease(AddinShmemInitLock);
        ereport(WARNING,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("table tracker: invalid DSA handle obtained"),
                 errdetail("DSA handle validation failed"),
                 errhint("DSA might have been corrupted during creation")));
        return;
    }

    handlers->table_handle = dshash_get_hash_table_handle(table);
    if (handlers->table_handle == DSHASH_HANDLE_INVALID)
    {
        LWLockRelease(AddinShmemInitLock);
        ereport(WARNING,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("table tracker: invalid hash table handle obtained"),
                 errdetail("Hash table handle validation failed")));
        return;
    }

    dsa_pin(seg);
    dsa_pin_mapping(seg);

    ereport(DEBUG2,
            (errmsg("table tracker: DSA pinned for persistence"),
             errdetail("Segment will remain allocated across backend lifetimes")));

    ereport(LOG,
            (errmsg("table tracker: initialization completed successfully"),
             errdetail("DSA handle: valid, Hash table: ready, Lock: acquired"),
             errcontext("First-time shared memory setup")));

    tracker_detach_all(table, seg);

    LWLockRelease(AddinShmemInitLock);

    ereport(LOG,
            (errmsg("table tracker: shared memory startup completed"),
             errdetail("Ready for table tracking operations"),
             errcontext("Extension ready state")));
}

void _PG_init(void)
{
    ereport(LOG,
            (errmsg("table tracker: loading extension"),
             errdetail("Version: 1.0, PostgreSQL: %s", PG_VERSION_STR),
             errcontext("Extension load phase")));

    prev_shmem_request_hook = shmem_request_hook;
    shmem_request_hook = tracker_shmem_request;

    prev_shmem_startup_hook = shmem_startup_hook;
    shmem_startup_hook = tracker_shmem_startup;

    ereport(DEBUG1,
            (errmsg("table tracker: memory hooks registered"),
             errdetail("shmem_request: %p, shmem_startup: %p",
                       tracker_shmem_request, tracker_shmem_startup)));

    prev_ExecutorStart = ExecutorStart_hook;
    ExecutorStart_hook = track_executor_start;

    ereport(DEBUG1,
            (errmsg("table tracker: executor hook registered"),
             errdetail("Hook function: %p", track_executor_start)));

    ereport(LOG,
            (errmsg("table tracker: extension loaded successfully"),
             errdetail("Hooks installed, ready for initialization"),
             errcontext("Extension _PG_init completion")));
}

void _PG_fini(void)
{
    ereport(LOG, (errmsg("table tracker: starting extension cleanup")));

    ExecutorStart_hook = prev_ExecutorStart;
    shmem_request_hook = prev_shmem_request_hook;
    shmem_startup_hook = prev_shmem_startup_hook;

    ereport(LOG,
            (errmsg("table tracker: extension unloaded successfully"),
             errdetail("Hooks uninstalled"),
             errcontext("Extension _PG_fini completion")));
}