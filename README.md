# Table Change Tracker Extension

A lightweight PostgreSQL extension that helps monitor when tables are last modified by INSERT, UPDATE, or DELETE operations.

## 📋 Overview

This extension provides a simple mechanism to track the most recent modification timestamp for selected tables in your database. It's designed to be efficient and unobtrusive, using shared memory structures to minimize performance impact.

## ✨ Features

- **🔄 Automatic Tracking**: Automatically updates timestamps when tracked tables are modified

- **🎯 Selective Monitoring**: Choose which tables to monitor and which to ignore

- **⚡ Bulk Operations**: Get timestamps for multiple tables at once

- **📊 Manual Control**: Optionally set timestamps manually when needed

- **🛠️ Low Overhead**: Uses dynamic shared memory

## 🚀 Installation

### 1. Build the extension

```bash
make
sudo make install
```

### 2. Enable in PostgreSQL

```sql
CREATE EXTENSION table_change_tracker;
```

### 3. Configure PostgreSQL

This extension requires access to PostgreSQL shared memory. Add the following to your postgresql.conf file.
Add to postgresql.conf:

```conf
shared_preload_libraries = 'table_change_tracker'
```

### 4. Restart PostgreSQL

After modifying the configuration, restart PostgreSQL.

```bash
sudo systemctl restart postgresql   # For systemd systems
pg_ctl restart                     # For manual installations
```

## 🔧 Functions

Enables tracking for the specified table. Returns true on success.

```c
enable_table_tracking(table_name regclass)
```

Disables tracking for the specified table. Returns true if tracking was successfully disabled.

```c
disable_table_tracking(table_name regclass)
```

Checks whether a table is currently being tracked. Returns true if the table is tracked.

```c
is_table_tracked(table_name regclass)
```

Returns the last modification timestamp for a tracked table. Returns NULL if the table is not tracked or hasn't been modified since tracking began.

```c
get_last_timestamp(table_name regclass)
```

Returns an array of timestamps for multiple tables. Useful for checking many tables at once.

```c
get_last_timestamps(tables_names regclass[])
```

Manually sets the last modification timestamp for a table. Returns true if the table is tracked and the timestamp was updated.

```c
set_last_timestamp(table_name regclass, last_timestamp timestamptz)
```

## 💡 Usage Example

```sql
-- Enable tracking for specific tables
SELECT enable_table_tracking('public.users');
SELECT enable_table_tracking('public.orders');
```

```sql
-- Check if a table is tracked
SELECT is_table_tracked('public.users');  -- Returns: true
```

```sql
-- Get the last modification time
SELECT get_last_timestamp('public.users');
```

```sql
-- Get timestamps for multiple tables
SELECT get_last_timestamps(ARRAY['public.users', 'public.orders']::regclass[]);
```

```sql
-- Manually update a timestamp (useful for data migrations)
SELECT set_last_timestamp('public.users', NOW());
```

```sql
-- Disable tracking when no longer needed
SELECT disable_table_tracking('public.orders');
```

## ⚙️ How It Works

The extension hooks into PostgreSQL's query execution process to detect when INSERT, UPDATE, or DELETE
operations occur on tracked tables. When such an operation is detected,
it updates the corresponding timestamp in a shared memory hash table.

## ⚠️ Limitations

- Only tracks DML operations (INSERT, UPDATE, DELETE)
- Does not track DDL operations (ALTER TABLE, TRUNCATE, etc.)
- Timestamps are stored in shared memory and will be lost on server restart
- Requires appropriate permissions to install and use

**Performance Considerations:**

The extension is designed to have minimal performance impact:

Only incurs overhead for tracked tables

## 📋 Requirements

- **PostgreSQL**: Version 12 or later
- **Permissions**: Superuser or appropriate extension privileges
- **Memory**: Sufficient shared memory for tracked tables

## 📄 License

This extension is released under the MIT License. See the [LICENSE](LICENSE) file for details.
