#!/bin/bash

host=localhost
port=5432
dbuser=postgres

read -p "DB host: [$host]" tmp
if [ -z ${tmp+x} ]; then : else host=$tmp; fi

read -p "DB port: [$port]" tmp
if [ -z ${tmp+x} ]; then : else port=$tmp; fi

read -p "DB user: [$dbuser]" tmp
if [ -z ${tmp+x} ]; then : else dbuser=$tmp; fi

read -sp 'DB pass: ' dbpass

export PGPASSWORD=$dbpass
psql -h $host -U $dbuser -p $port -a -w -f create_streamers_database.sql
