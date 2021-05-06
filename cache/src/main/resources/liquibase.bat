@echo off

set dbhost=localhost
set /p dbhost=Database hostname (default - %dbhost%)?:

set dbport=5432
set /p dbport=Database port (default - %dbport%)?:

set dbusername=
set /p dbusername=Database user name (default - %dbusername%)?:

set dbpassword=
set /p dbpassword=Database password (default - %dbpassword%)?:

set dbname=
set /p dbname=Database name (default - %dbname%)?:

set dbaction=updateSql
set /p dbaction=Database action [update/updateSql] (default - %dbaction%)?:

chcp 65001
java '-Dfile.encoding=UTF-8' -cp liquibase-core-3.6.1.jar;logback-classic-1.2.3.jar;logback-core-1.2.3.jar;postgresql-42.2.5.jar;slf4j-api-1.7.25.jar;snakeyaml-1.25.jar liquibase.integration.commandline.Main --changeLogFile=changelog.yaml --url=jdbc:postgresql://%dbhost%:%dbport%/%dbname% --username=%dbusername% --password=%dbpassword% %dbaction%
