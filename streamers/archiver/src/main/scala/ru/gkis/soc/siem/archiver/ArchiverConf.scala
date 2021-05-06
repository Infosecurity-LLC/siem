package ru.gkis.soc.siem.archiver

import java.time.Duration

import com.typesafe.config.Config
import org.apache.spark.sql.SaveMode


trait ArchiverConf {

    protected val appConf: Config

    val archiverRecordsTTL: Duration = appConf.getDuration("app.archiver.archiverRecordsTTL")

    val saveMode: SaveMode = appConf.getEnum(classOf[SaveMode], "app.archiver.saveMode")

}
