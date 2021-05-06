package ru.gkis.soc.siem.model.access

sealed trait RuleResult
case object Allowed extends RuleResult
case object Restricted extends RuleResult
case object Undefined extends RuleResult
