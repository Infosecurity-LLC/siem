package ru.gkis.soc.siem.cache

import ru.gkis.soc.siem.cache.adapters.{ScheduleGroupAdapter, SubjectAdapter}
import ru.gkis.soc.siem.model.access.{Host, Organization, RuleObject, RuleResult, RuleType, Schedule, Subject}

import java.time.LocalDateTime

class WriteMetaCache(conf: CacheConfig) extends MetaCache(conf) {

    import sqlContext._
    import sqlContext.dsl._

    def subj(orgId: Int, login: Option[String], domain: Option[String]): List[SubjectAdapter] = {
        val select = quote {
            schema
                .subject
                .filter(s => s.orgId == lift(orgId) && s.login == lift(login) && s.userDomain == lift(domain))
                .take(1)
        }

        dsl run select
    }

    def add(orgId: Int, s: Subject): Int = {
        val insert = quote {
            schema
                .subject
                .insert(
                    _.orgId -> lift(orgId),
                    _.email -> lift(s.email),
                    _.groupId -> lift(s.groupId),
                    _.login -> lift(s.login),
                    _.monitored -> lift(s.monitored),
                    _.phone -> lift(s.phone),
                    _.startWork -> lift(s.startWork),
                    _.userDomain -> lift(s.userDomain),
                    _.userName -> lift(s.userName)
                ).returningGenerated(_.id)
        }
        dsl run insert
    }

    def org(org: String): List[Organization] = {
        val select = quote {
            schema
                .organizations
                .filter(o => o.shortName == lift(org))
                .take(1)
        }

        dsl run select
    }

    def add(o: Organization): Int = {
        val insert = quote {
            schema
                .organizations
                .insert(lift(o)).returningGenerated(_.id)
        }

        dsl run insert
    }

    def host(orgId: Int, hostName: Option[String], ip: Option[String]): List[Host] = {
        val select = quote {
            schema
                .hosts
                .filter(h => h.hostIp == lift(ip) && h.hostName == lift(hostName) && h.orgId == lift(orgId))
                .take(1)
        }

        dsl run select
    }

    def add(host: Host): Int = {
        val insert = quote {
            schema
                .hosts
                .insert(lift(host)).returningGenerated(_.id)
        }

        dsl run insert
    }

    def obj(typ: String, path: Option[String], name: Option[String]): List[RuleObject] = {
        val select = quote {
            schema
                .objects
                .filter(o =>
                    o.objType == lift(typ) &&
                        o.objPath == lift(path) &&
                        o.objName == lift(name)
                )
                .take(1)
        }

        dsl run select
    }

    def add(ro: RuleObject): Int = {
        val insert = quote {
            schema
                .objects
                .insert(lift(ro)).returningGenerated(_.id)
        }

        dsl run insert
    }

    def add(
            login: Option[String],
            userName: Option[String],
            orgId: Int,
            groupId: Int,
            userDomain: Option[String]): Int = {

        val insert = quote {
            schema
                .subject
                .insert(
                    _.login -> lift(login),
                    _.orgId -> lift(orgId),
                    _.userName -> lift(userName),
                    _.groupId -> lift(groupId),
                    _.monitored -> lift(true),
                    _.userDomain -> lift(userDomain),
                    _.startWork -> lift(LocalDateTime.now())
                )
                .returningGenerated(_.id)
        }

        dsl run insert
    }

    def rule(subject: Int,
             source: Option[Int],
             destination: Option[Int],
             `object`: Option[Int],
             result: RuleResult,
             usecaseId: String,
             `type`: RuleType,
             schedule: Int,
             aux1: Option[String],
             aux2: Option[String]): List[Int] = {
        val select = quote {
            schema
                .rules
                .filter(r =>
                        r.subject == lift(subject) &&
                        r.source == lift(source) &&
                        r.destination == lift(destination) &&
                        r.`object` == lift(`object`) &&
                        r.result == lift(result) &&
                        r.usecaseId == lift(usecaseId) &&
                        r.`type` == lift(`type`) &&
                        r.schedule == lift(schedule) &&
                        r.aux1 == lift(aux1) &&
                        r.aux2 == lift(aux2)
                )
                .map(_.id)
                .take(1)

        }

        dsl run select
    }

    def add(subject: Int,
            source: Option[Int],
            destination: Option[Int],
            `object`: Option[Int],
            result: RuleResult,
            usecaseId: String,
            `type`: RuleType,
            schedule: Int,
            aux1: Option[String],
            aux2: Option[String]): Unit = {
        val insert = quote {
            schema
                .rules
                .insert(
                    _.subject -> lift(subject),
                    _.source -> lift(source),
                    _.destination -> lift(destination),
                    _.`object` -> lift(`object`),
                    _.result -> lift(result),
                    _.usecaseId -> lift(usecaseId),
                    _.`type` -> lift(`type`),
                    _.schedule -> lift(schedule),
                    _.aux1 -> lift(aux1),
                    _.aux2 -> lift(aux2)
                )
        }

        dsl run insert
    }

    def add(s: Schedule): Unit = {
        val insert = quote {
            schema
                .schedule
                .insert(
                    _.timeFrom -> lift(s.timeFrom),
                    _.timeTo -> lift(s.timeTo),
                    _.daysWork -> lift(s.daysWork),
                    _.daysWeekend -> lift(s.daysWeekend),
                    _.isCalendar -> lift(s.isCalendar),
                    _.groupId -> lift(s.groupId)
                )
        }

        dsl run insert
    }

    def add(name: String): Int = {
        implicit val sgInsertMeta = insertMeta[ScheduleGroupAdapter](_.id)
        val sg = ScheduleGroupAdapter(0, name)
        val insert = quote {
            schema
                .scheduleGroups
                .insert(lift(sg))
                .returningGenerated(_.id)
        }

        dsl run insert
    }

    def update(id: Int, name: String): Unit = {
        val update = quote {
            schema
                .scheduleGroups
                .filter(_.id == lift(id))
                .update(_.groupName -> lift(name))
        }

        dsl run update
    }
}
