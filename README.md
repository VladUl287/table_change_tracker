<!-- Build WSL -->
cd /mnt/host/c/Users/User/source/repos/cpgext/
make

<!-- Copy to Docker -->
docker cp table_change_tracker.so postgres-container:/usr/lib/postgresql/16/lib/
docker cp table_change_tracker.control postgres-container:/usr/share/postgresql/16/extension/
docker cp table_change_tracker--1.0.sql postgres-container:/usr/share/postgresql/16/extension/