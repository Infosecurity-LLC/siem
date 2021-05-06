package ru.gkis.soc.siem.model

import java.time.LocalDateTime

case class DomainLogin(groupId: Int,
                       userName: Option[String],
                       phone: Option[String],
                       email: Option[String],
                       monitored: Boolean,
                       startWork: LocalDateTime)
