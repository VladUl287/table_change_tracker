\echo Use "CREATE EXTENSION table_change_tracker" to load this file. \quit

CREATE OR REPLACE FUNCTION get_last_timestamp(table_name TEXT)
RETURNS TIMESTAMP WITH TIME ZONE
AS 'MODULE_PATHNAME', 'get_last_timestamp'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION dump_hash_table()
RETURNS void
AS 'MODULE_PATHNAME', 'dump_hash_table'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION enable_table_tracking(table_name TEXT)
RETURNS BOOLEAN
AS 'MODULE_PATHNAME', 'enable_table_tracking'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION disable_table_tracking(table_name TEXT)
RETURNS BOOLEAN
AS 'MODULE_PATHNAME', 'disable_table_tracking'
LANGUAGE C STRICT;
