\echo Use "CREATE EXTENSION table_change_tracker" to load this file. \quit

CREATE OR REPLACE FUNCTION get_last_timestamp(table_name TEXT)
RETURNS TIMESTAMP WITH TIME ZONE
AS 'MODULE_PATHNAME', 'get_last_timestamp'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION get_last_timestamp_by_oid(table_oid OID)
RETURNS TIMESTAMP WITH TIME ZONE
AS 'MODULE_PATHNAME', 'get_last_timestamp_by_oid'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION enable_table_tracking(table_name TEXT)
RETURNS BOOLEAN
AS 'MODULE_PATHNAME', 'enable_table_tracking'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION disable_table_tracking(table_name TEXT)
RETURNS BOOLEAN
AS 'MODULE_PATHNAME', 'disable_table_tracking'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION is_table_tracked(table_name TEXT)
RETURNS BOOLEAN
AS 'MODULE_PATHNAME', 'is_table_tracked'
LANGUAGE C STRICT;
