#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "tcop/utility.h"
#include "executor/executor.h"

PG_MODULE_MAGIC;

static ProcessUtility_hook_type prev_ProcessUtility = NULL;
static ExecutorStart_hook_type prev_ExecutorStart = NULL;

static uint64 change_counter = 0;

static void track_utility(
    PlannedStmt *pstmt, const char *queryString, bool readOnlyTree, ProcessUtilityContext context,
    ParamListInfo params, QueryEnvironment *queryEnv, DestReceiver *dest, QueryCompletion *qc);

static void track_executor_start(QueryDesc *queryDesc, int eflags);

void _PG_init(void);
void _PG_fini(void);

PG_FUNCTION_INFO_V1(hello_world);
PG_FUNCTION_INFO_V1(get_change_counter);

Datum hello_world(PG_FUNCTION_ARGS)
{
    PG_RETURN_TEXT_P(cstring_to_text("Hello from table change tracker extension!"));
}

Datum get_change_counter(PG_FUNCTION_ARGS)
{
    PG_RETURN_INT64(1);
}

static void track_utility(
    PlannedStmt *pstmt, const char *queryString, bool readOnlyTree, ProcessUtilityContext context,
    ParamListInfo params, QueryEnvironment *queryEnv, DestReceiver *dest, QueryCompletion *qc)
{
    if (prev_ProcessUtility)
        prev_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
    else
        standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
}

static void track_executor_start(QueryDesc *queryDesc, int eflags)
{
    CmdType operation = queryDesc->operation;

    if (operation == CMD_INSERT || operation == CMD_UPDATE || operation == CMD_DELETE)
    {
        change_counter++;
    }

    if (prev_ExecutorStart)
        prev_ExecutorStart(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);
}

void _PG_init(void)
{
    prev_ExecutorStart = ExecutorStart_hook;
    ExecutorStart_hook = track_executor_start;

    prev_ProcessUtility = ProcessUtility_hook;
    ProcessUtility_hook = track_utility;

    ereport(LOG, (errmsg("Table Change Tracker: Extension loaded")));
}

void _PG_fini(void)
{
    ExecutorStart_hook = prev_ExecutorStart;
    ProcessUtility_hook = prev_ProcessUtility;

    ereport(LOG, (errmsg("Table Change Tracker: Extension unloaded")));
}