package ru.gkis.soc.siem.reassembler

import com.typesafe.config.Config

import scala.concurrent.duration.FiniteDuration

trait ReassemblyConfig {
    protected val appConf: Config
}
