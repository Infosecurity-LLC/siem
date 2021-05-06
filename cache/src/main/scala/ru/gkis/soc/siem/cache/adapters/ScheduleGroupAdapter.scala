package ru.gkis.soc.siem.cache.adapters

import ru.gkis.soc.siem.model.access.{Schedule, ScheduleGroup}

private[cache] case class ScheduleGroupAdapter(id: Int, groupName: String) {
    def scheduleGroup(schedule: List[Schedule]): ScheduleGroup = {
        ScheduleGroup(id, groupName, schedule)
    }
}
