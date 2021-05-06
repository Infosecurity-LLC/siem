package ru.gkis.soc.siem.cache

import com.typesafe.config.Config

trait CacheConfig {

    protected val appConf: Config

    lazy val metabaseConfig: Config = appConf.getConfig("app.streamers_meta")
    lazy val maximumAsyncPoolSize: Int = appConf.getInt("app.streamers_meta.maximumPoolSize")
}
