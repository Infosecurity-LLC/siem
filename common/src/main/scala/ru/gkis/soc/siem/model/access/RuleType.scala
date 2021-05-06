package ru.gkis.soc.siem.model.access

sealed trait RuleType
case object WindowsLogon extends RuleType
case object WindowsObject extends RuleType
case object WindowsProcess extends RuleType
case object LinuxLogon extends RuleType
case object LinuxObject extends RuleType
case object LinuxProcess extends RuleType
case object VpnLogon extends RuleType
case object DatabaseLogon extends RuleType
case object DatabaseObject extends RuleType
case object FirewallConnection extends RuleType
