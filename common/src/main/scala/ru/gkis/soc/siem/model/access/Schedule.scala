package ru.gkis.soc.siem.model.access

import java.time.LocalTime

case class Schedule(id: Int,
                    groupId: Int,
                    timeFrom: LocalTime,
                    timeTo: LocalTime,
                    daysWork: Byte,
                    daysWeekend: Byte,
                    isCalendar: Boolean)
