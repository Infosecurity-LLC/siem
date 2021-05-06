package ru.gkis.soc.siem.filter

sealed trait Split

case class Event(value: String) extends Split

case class Statistic(filteredCount: Int, approvedCount: Int) extends Split
