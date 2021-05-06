## First you need to prepare DB, without it insert with auto ID values will NOT work

```sql
SELECT 'SELECT SETVAL(' ||
       quote_literal(quote_ident(PGT.schemaname) || '.' || quote_ident(S.relname)) ||
       ', COALESCE(MAX(' ||quote_ident(C.attname)|| '), 1) ) FROM ' ||
       quote_ident(PGT.schemaname)|| '.'||quote_ident(T.relname)|| ';'
FROM pg_class AS S,
     pg_depend AS D,
     pg_class AS T,
     pg_attribute AS C,
     pg_tables AS PGT
WHERE S.relkind = 'S'
  AND S.oid = D.objid
  AND D.refobjid = T.oid
  AND D.refobjid = C.attrelid
  AND D.refobjsubid = C.attnum
  AND T.relname = PGT.tablename
ORDER BY S.relname;
```

For current DB you get something like

```sql
SELECT SETVAL('public.device_categories_id_seq', COALESCE(MAX(id), 1) ) FROM public.device_categories;
SELECT SETVAL('public.device_sub_categories_id_seq', COALESCE(MAX(id), 1) ) FROM public.device_sub_categories;
SELECT SETVAL('public.device_types_id_seq', COALESCE(MAX(id), 1) ) FROM public.device_types;
SELECT SETVAL('public.device_vendors_id_seq', COALESCE(MAX(id), 1) ) FROM public.device_vendors;
SELECT SETVAL('public.event_mappers_id_seq', COALESCE(MAX(id), 1) ) FROM public.event_mappers;
SELECT SETVAL('public.event_parsers_id_seq', COALESCE(MAX(id), 1) ) FROM public.event_parsers;
SELECT SETVAL('public.event_validators_id_seq', COALESCE(MAX(id), 1) ) FROM public.event_validators;
SELECT SETVAL('public.hosts_id_seq', COALESCE(MAX(id), 1) ) FROM public.hosts;
SELECT SETVAL('public.logins_id_seq', COALESCE(MAX(id), 1) ) FROM public.subject;
SELECT SETVAL('public.mappers_id_seq', COALESCE(MAX(id), 1) ) FROM public.mappers;
SELECT SETVAL('public.objects_id_seq1', COALESCE(MAX(id), 1) ) FROM public.objects;
SELECT SETVAL('public.organizations_id_seq', COALESCE(MAX(id), 1) ) FROM public.organizations;
SELECT SETVAL('public.parsers_id_seq', COALESCE(MAX(id), 1) ) FROM public.parsers;
SELECT SETVAL('public.py_scripts_id_seq', COALESCE(MAX(id), 1) ) FROM public.py_scripts;
SELECT SETVAL('public.rules_id_seq', COALESCE(MAX(id), 1) ) FROM public.rules;
SELECT SETVAL('public.schedule_groups_id_seq', COALESCE(MAX(id), 1) ) FROM public.schedule_groups;
SELECT SETVAL('public.schedule_id_seq', COALESCE(MAX(id), 1) ) FROM public.schedule;
SELECT SETVAL('public.validators_id_seq', COALESCE(MAX(id), 1) ) FROM public.validators;
```

## Upload Windows logon rules

```bash
java -cp "control.jar;postgresql-42.2.5.jar;logback-core-1.2.3.jar;logback-classic-1.2.3.jar" \ 
         ru.gkis.soc.siem.controluploader.WindowsLogonRuleUploader \
         -f win_authorization_20201116.csv \  
         -l liquibase \ 
         -p **password** \
         -u jdbc:postgresql://**db_host**:5432/streamers
```

# Upload Windows catalog and files access rules

```bash
java -cp "control.jar;postgresql-42.2.5.jar;logback-core-1.2.3.jar;logback-classic-1.2.3.jar" \ 
         ru.gkis.soc.siem.controluploader.WindowsObjectAccessUploader \
         -f test_catalog_access.csv \  
         -l liquibase \ 
         -p **password** \
         -u jdbc:postgresql://**db_host**:5432/streamers
```