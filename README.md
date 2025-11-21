<!-- Build WSL -->
cd /mnt/host/c/Users/User/source/repos/cpgext/
make

<!-- Run wsl -->
wsl -d Debian

<!-- Copy to Docker -->
docker cp table_change_tracker.so vibrant_murdock:/usr/lib/postgresql/16/lib/ && docker cp table_change_tracker.control vibrant_murdock:/usr/share/postgresql/16/extension/ && docker cp table_change_tracker--1.0.sql vibrant_murdock:/usr/share/postgresql/16/extension/