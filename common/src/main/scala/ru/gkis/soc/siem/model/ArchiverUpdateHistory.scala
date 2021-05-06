package ru.gkis.soc.siem.model

import java.time.LocalDateTime

case class ArchiverUpdateHistory(id: Long, tableName: String, lastUpdateAt: LocalDateTime)
