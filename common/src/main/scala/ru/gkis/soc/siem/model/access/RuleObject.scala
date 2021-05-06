package ru.gkis.soc.siem.model.access

case class RuleObject(id: Int,
                      objType: String,
                      objPath: Option[String],
                      objName: Option[String],
                      port: Option[Int])
