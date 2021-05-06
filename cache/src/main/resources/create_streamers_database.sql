CREATE DATABASE streamers
ENCODING 'UTF-8'
LC_COLLATE 'ru_RU.UTF-8'
LC_CTYPE 'ru_RU.UTF-8'
TEMPLATE template0;

create user liquibase password '12345678';

grant all privileges on database streamers to liquibase;
