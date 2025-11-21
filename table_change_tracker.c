#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "tcop/utility.h"
#include "executor/executor.h"
#include "storage/shmem.h"

PG_MODULE_MAGIC;

static ExecutorStart_hook_type prev_ExecutorStart = NULL;

typedef struct
{
    int64 counter;
} tracker_data_t;

static tracker_data_t *tracker_data = NULL;

void _PG_init(void);
void _PG_fini(void);

PG_FUNCTION_INFO_V1(get_change_counter);

Datum get_change_counter(PG_FUNCTION_ARGS)
{
    PG_RETURN_INT64(tracker_data->counter);
}

static void shared_memory_shmem_startup(void)
{
    bool found;

    tracker_data = (tracker_data_t *)ShmemInitStruct("tracker_data", sizeof(tracker_data_t), &found);

    if (!found)
    {
        memset(tracker_data, 0, sizeof(tracker_data_t));
        tracker_data->counter = 32311;
    }
}

static void track_executor_start(QueryDesc *queryDesc, int eflags)
{
    CmdType operation = queryDesc->operation;

    if (operation == CMD_INSERT || operation == CMD_UPDATE || operation == CMD_DELETE)
    {
        tracker_data->counter++;
    }

    if (prev_ExecutorStart)
        prev_ExecutorStart(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);
}

void _PG_init(void)
{
    shared_memory_shmem_startup();

    prev_ExecutorStart = ExecutorStart_hook;
    ExecutorStart_hook = track_executor_start;

    ereport(LOG, (errmsg("Table Change Tracker: Extension loaded")));
}

void _PG_fini(void)
{
    ExecutorStart_hook = prev_ExecutorStart;

    ereport(LOG, (errmsg("Table Change Tracker: Extension unloaded")));
}