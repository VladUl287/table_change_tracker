EXTENSION = table_change_tracker
DATA = table_change_tracker--1.0.sql
MODULE_big = table_change_tracker
OBJS = table_change_tracker.o

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)