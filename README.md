### SIEM 2.0

To setup and run this project clone it from repository, navigate to project folder and run
```shell script
./gradlew clean build
```

In IDEA Scala compiler options add additional parameter `-Xfatal-warnings`, `-feature`, `-deprecation:false` to strictly check pattern match exhaustiveness
Normalizer test packages carry test message player.
It can send some fortigate messages into local Kafka.

### Setup development ENV

* install [JDK 1.8](https://www.oracle.com/java/technologies/javase/javase-jdk8-downloads.html)
* Install latest [Virtual Box](https://www.virtualbox.org/wiki/Downloads)
* Download [HDP Sandbox VM Image](https://archive.cloudera.com/hwx-sandbox/hdp/hdp-2.6.5/HDP_2.6.5_virtualbox_180626.ova) (use wget or any download manager). Import it to VirtualBox and run, first run take around 30-60 minutes to complete start.
* Install [Docker](https://docs.docker.com/engine/install/)
* Setup PostrgeSQL database, via using this docker-compose.yaml. Change `*PROJECT_ROOT*` to absolute path to project 

```dockerfile
version: '3'
services:
  postgres:
    image: "postgres:10-alpine"
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: 12345678
    volumes:
      - *PROJECT_ROOT*/cache/src/main/resources/create_streamers_database.sql:/docker-entrypoint-initdb.d/1-init.sql
```

with command `docker compose up -d`

* Setup Elastic Search

```dockerfile
image: docker.elastic.co/elasticsearch/elasticsearch:7.4.0
      container_name: elasticsearch
      environment:
        - xpack.security.enabled=false
        - discovery.type=single-node
      ulimits:
        memlock:
          soft: -1
          hard: -1
        nofile:
          soft: 65536
          hard: 65536
      cap_add:
        - IPC_LOCK
      volumes:
        - ./elasticsearch-data:/usr/share/elasticsearch/data
      ports:
        - 9200:9200
        - 9300:9300
``` 

* Set Gradle liquibase configuration, add following lines to Gradle config (by default: `~/.gradle/gradle.properties`):
```hocon
systemProp.liquibase_user=liquibase
systemProp.liquibase_password=12345678
```

* Run `Gradle` task to initialize database `Gradle -> Tasks -> liquibase -> update`

### Prepare project

* In `resources` dir for sub-project `common` create directory `local`

```shell script
cd common/src/main/resources
mkdir local
```

* Copy logging configuration

```shell script
cp logback.xml local/logback.xml
```

* Copy metrics configuration and comment all lines inside file 

```shell script
sed -e 's/^/#/' metrics.properties > local/metrics.properties
```

* Create local configuration file

```shell script
cd local
nano normalizer.conf
```

With following content

```hocon
app {
  spark {
    app.name = "Streamer"
    master = "local[2]"
    metrics.namespace = "siem_"
  }
  kafka {
    input {
      bootstrap.servers = "localhost:60000"
      group.id = "normalizer"
      topics = ["fortigate"]
    }
    output {
      producer = {
        bootstrap.servers = "localhost:60000"
        topic.mappings {
          // message state to topic name
          normalized = "normalized"
          error = "error"
          invalid = "invalid"
          raw = "raw"
          chain = "chain"
        }
      }
    }
  }

  streamers_meta {
    jdbcUrl = "jdbc:postgresql://localhost:5432/streamers"
    username = postgres
    password = 12345678
  }
  normalizer {
    //  available modes:
    //  * `as-is` - does nothing
    //  * `now` - sets `data.time` to current timestamp
    //  * `shift` - shifts `data.time` by time.shift.value
    time.shift.mode = "now"
  }
}
```

### Configure HDFS and Kafka

* Open [Ambari](http://localhost:8080/) to start service configuration 
* Select `Ranger` go to `configs` -> `Ranger Plugins` and disable all plugins, click save and approve all request
* Restart VirtualBox machine via `send shutdown signal`
* Remove following Services from Sandbox via `Service Actions` -> `Delete Service`
    * SQOOP
    * Falcon
    * Storm
    * Flume
    * Ambari Infra
    * Atlas
    * Knox
    * Ranger
    * Zeppelin Notebook
    * Druid
    * Superset
* Configure Kafka
    * Kafka broker -> listeners = PLAINTEXT://0.0.0.0:60000
    * Advanced kafka-broker -> port = 60000
    * Advanced ranger-kafka-audit -> Audit to HDFS = false
    * Custom kafka-broker (add property) ->
        * advertised.listeners = PLAINTEXT://sandbox-hdp.hortonworks.com:60000
* Configure HDFS
    * Advanced hdfs-site ->
        * dfs.datanode.address = sandbox-hdp.hortonworks.com:50010
        * dfs.datanode.http.address = sandbox-hdp.hortonworks.com:50075
        * dfs.datanode.https.address = sandbox-hdp.hortonworks.com:50475
        * dfs.datanode.ipc.address = sandbox-hdp.hortonworks.com:8010
        * dfs.journalnode.http-address = sandbox-hdp.hortonworks.com:8480
        * dfs.journalnode.https-address = sandbox-hdp.hortonworks.com:8481
    * Advanced ranger-hdfs-audit -> Audit to HDFS = false
    * Advanced ranger-hdfs-plugin-properties -> Enable Ranger for HDFS = false
    * Custom hdfs-site (add property) ->
        * dfs.client.use.datanode.hostname = true
        * dfs.datanode.use.datanode.hostname = true
    * Custom core-site ->
        * hadoop.proxyuser.root.hosts = *
    * Custom core-site (add property) ->
        * hadoop.proxyuser.tech_siem.groups = *
        * hadoop.proxyuser.tech_siem.hosts = *
    * Custom hdfs-site (add property) ->
        * dfs.client.use.datanode.hostname = true
        * dfs.datanode.use.datanode.hostname = true
* Manually restart all services with restart icon
* Add `127.0.0.1 sandbox-hdp.hortonworks.com` to `hosts` file on host machine

### IDEA Run configurations

Normalizer:
. Change `*PROJECT_ROOT*` to absolute path to project
* VM Options: `-Dconfig.file=*PROJECT_ROOT*/common/src/main/resources/local/normalizer.conf -Dquill.binds.log=true -Dspark.metrics.conf=*PROJECT_ROOT*/common/src/main/resources/local/metrics.properties -Dlogback.configurationFile=*PROJECT_ROOT*/common/src/main/resources/local/logback.xml`

KafkaPlayer:
* Program arguments: `sandbox-hdp.hortonworks.com:60000 fortigate /fortigate.txt` 
