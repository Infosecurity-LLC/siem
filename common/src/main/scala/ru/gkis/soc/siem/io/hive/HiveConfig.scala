package ru.gkis.soc.siem.io.hive

import com.typesafe.config.Config

trait HiveConfig {

    protected val appConf: Config

    val propertyName = "hive.metastore.uris"
    val hiveUri: (String, String) = propertyName -> appConf.getConfig("app").getString(propertyName)

    val hiveTable: String = appConf.getConfig("app").getString("hive.tableName")

}
