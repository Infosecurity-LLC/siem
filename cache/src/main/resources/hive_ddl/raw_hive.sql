drop table raw;
CREATE EXTERNAL TABLE raw (
    id  string,
    raw  string,
    collector_location_fqdn  string,
    collector_location_host  string,
    collector_location_hostname  string,
    collector_location_ip  string,
    collector_inputId  string,
    collector_organization  string,
    eventTime  bigint,
    devType  string,
    eventSource_fqdn  string,
    eventSource_host  string,
    eventSource_hostname  string,
    eventSource_ip  string,
    severityId  int,
    severity  string,
    normalizedId  string
)
PARTITIONED BY (sys_org string, sys_year int, sys_month int, sys_day int)
STORED AS ORC
location '/archive/raw/';
msck repair table raw;
