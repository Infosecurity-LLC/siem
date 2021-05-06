package ru.gkis.soc.siem.router.dsl.model

case class ParsedMessage(key: Option[String], org: String, devType: String, raw: String)
