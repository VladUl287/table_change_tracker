\echo Use "CREATE EXTENSION table_change_tracker" to load this file. \quit

CREATE OR REPLACE FUNCTION get_last_timestamp(table_name TEXT)
RETURNS TIMESTAMP WITH TIME ZONE
AS 'MODULE_PATHNAME', 'get_last_timestamp'
LANGUAGE C STRICT;