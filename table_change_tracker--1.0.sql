\echo Use "CREATE EXTENSION table_change_tracker" to load this file. \quit

CREATE OR REPLACE FUNCTION hello_world()
RETURNS text
AS 'MODULE_PATHNAME', 'hello_world'
LANGUAGE C STRICT;