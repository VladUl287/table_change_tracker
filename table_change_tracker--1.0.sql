\echo Use "CREATE EXTENSION table_change_tracker" to load this file. \quit

CREATE OR REPLACE FUNCTION get_last_timestamp(table_name regclass)
RETURNS TIMESTAMP WITH TIME ZONE
AS 'MODULE_PATHNAME', 'get_last_timestamp'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION get_last_timestamps(tables_names regclass[])
RETURNS TIMESTAMP WITH TIME ZONE[]
AS 'MODULE_PATHNAME', 'get_last_timestamps'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION set_last_timestamp(table_name regclass, last_timestamp timestamp with time zone)
RETURNS BOOLEAN
AS 'MODULE_PATHNAME', 'set_last_timestamp'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION enable_table_tracking(table_name regclass)
RETURNS BOOLEAN
AS 'MODULE_PATHNAME', 'enable_table_tracking'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION disable_table_tracking(table_name regclass)
RETURNS BOOLEAN
AS 'MODULE_PATHNAME', 'disable_table_tracking'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION is_table_tracked(table_name regclass)
RETURNS BOOLEAN
AS 'MODULE_PATHNAME', 'is_table_tracked'
LANGUAGE C STRICT;
