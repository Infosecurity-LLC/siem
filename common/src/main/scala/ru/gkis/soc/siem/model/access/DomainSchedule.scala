package ru.gkis.soc.siem.model.access

import ru.gkis.soc.siem.model.Period

case class DomainSchedule(period: Period, daysWork: Byte, daysWeekend: Byte, isCalendar: Boolean)
