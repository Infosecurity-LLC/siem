drop table chain;
CREATE EXTERNAL TABLE chain (
    rawId string,
    normalizedId string,
    chain string,
    collector_location_fqdn string,
    collector_location_host string,
    collector_location_hostname string,
    collector_location_ip string,
    collector_inputId string,
    collector_organization string,
    eventTime bigint
  )
PARTITIONED BY (sys_org string, sys_year int, sys_month int, sys_day int)
STORED AS ORC
location '/archive/chain/';
msck repair table chain;
