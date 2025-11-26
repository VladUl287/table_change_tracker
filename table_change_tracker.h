#ifndef TABLE_TRACKER_H
#define TABLE_TRACKER_H

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

/* Structure to store shared memory handlers */
typedef struct
{
    dshash_table_handle table_handle;
    dsa_handle area_handle;
} handlers_t;

/* Structure to store table tracking data */
typedef struct
{
    char key[NAMEDATALEN];
    TimestampTz timestamp;
} tracker_data;

/* Global variables - only extern declarations */
extern ExecutorStart_hook_type prev_ExecutorStart;
extern handlers_t *handlers;
extern dshash_parameters dshash_params;

/* PostgreSQL module lifecycle functions */
extern void _PG_init(void);
extern void _PG_fini(void);

/* SQL-callable function declarations */
extern Datum get_last_timestamp(PG_FUNCTION_ARGS);
extern Datum dump_hash_table(PG_FUNCTION_ARGS);
extern Datum enable_table_tracking(PG_FUNCTION_ARGS);
extern Datum disable_table_tracking(PG_FUNCTION_ARGS);

#endif /* TABLE_TRACKER_H */