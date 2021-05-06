package ru.gkis.soc.siem.cache

import com.typesafe.scalalogging.LazyLogging
import ru.gkis.soc.siem.cache.adapters.{RuleAdapter, ScheduleGroupAdapter, SubjectAdapter}
import ru.gkis.soc.siem.model.access._
import ru.gkis.soc.siem.model._

import java.time.LocalDateTime

class MetaCache(conf: CacheConfig) extends LazyLogging {

    protected val sqlContext = new MetaCacheContext(conf)

    import sqlContext._
    import sqlContext.dsl._

    implicit val decodeRuleType: MappedEncoding[RuleType, String] = MappedEncoding[RuleType, String](_.toString)
    implicit val decodeRuleResult: MappedEncoding[RuleResult, Int] = MappedEncoding[RuleResult, Int] {
        case Allowed => 0
        case Restricted => 1
        case Undefined =>
            throw new RuntimeException("Rule with Undefined result can't be saved")
    }

    protected object schema {
        // avoid type annotations here cause this breaks macro generator making quill to generate dynamic queries
        // private modifier used to get rid of idea warnings
        val eventParsers: Quoted[EntityQuery[EventParser]] = quote {
            querySchema[EventParser]("event_parsers")
        }
        val parsers: Quoted[EntityQuery[Parser]] = quote {
            querySchema[Parser]("parsers")
        }
        val deviceTypes: Quoted[EntityQuery[DeviceType]] = quote {
            querySchema[DeviceType]("device_types")
        }
        val organizations: Quoted[EntityQuery[Organization]] = quote {
            querySchema[Organization]("organizations")
        }

        def activeOrganizations(since: LocalDateTime) = quote {
            organizations filter (org => (org.activeFrom < lift(since)) && org.activeTo.isEmpty)
        }

        val eventValidators: Quoted[EntityQuery[EventValidator]] = quote {
            querySchema[EventValidator]("event_validators")
        }
        val validators: Quoted[EntityQuery[Validator]] = quote {
            querySchema[Validator]("validators")
        }
        val eventMappers: Quoted[EntityQuery[EventMapper]] = quote {
            querySchema[EventMapper]("event_mappers")
        }
        val mappers: Quoted[EntityQuery[Mapper]] = quote {
            querySchema[Mapper]("mappers")
        }
        val vendors: Quoted[EntityQuery[Vendor]] = quote {
            querySchema[Vendor]("device_vendors")
        }
        val ipGeoInfoCity: Quoted[EntityQuery[IpGeoInfo]] = quote {
            querySchema[IpGeoInfo]("v_geoinfo_city")
        }
        val ipGeoInfoCountry: Quoted[EntityQuery[IpGeoInfoCountry]] = quote {
            querySchema[IpGeoInfoCountry]("v_geoinfo_country")
        }
        val scheduleGroups: Quoted[EntityQuery[ScheduleGroupAdapter]] = quote {
            querySchema[ScheduleGroupAdapter]("schedule_groups")
        }
        val schedule: Quoted[EntityQuery[Schedule]] = quote {
            querySchema[Schedule]("schedule")
        }
        val subject: Quoted[EntityQuery[SubjectAdapter]] = quote {
            querySchema[SubjectAdapter]("subject")
        }
        val objects: Quoted[EntityQuery[RuleObject]] = quote {
            querySchema[RuleObject]("objects")
        }
        val rules: Quoted[EntityQuery[RuleAdapter]] = quote {
            querySchema[RuleAdapter]("rules", _.usecaseId -> "use_case_id")
        }
        val hosts: Quoted[EntityQuery[Host]] = quote {
            querySchema[Host]("hosts")
        }
        val scripts: Quoted[EntityQuery[PyScript]] = quote {
            querySchema[PyScript]("py_scripts")
        }
    }

    def parserPreferences(sinceTime: LocalDateTime): List[ParserConfig] = {
        val select = quote {
            for {
                ep <- schema.eventParsers
                org <- schema.activeOrganizations(sinceTime) join (org => org.id == ep.orgId)
                p <- schema.parsers join (p => p.id == ep.parserId)
                dt <- schema.deviceTypes join (dt => dt.id == ep.deviceTypeId)
            }
                yield ParserConfig(p.name, p.version, org.shortName, dt.devType)
        }

        dsl run select
    }

    def validatorPreferences(sinceTime: LocalDateTime): List[ValidatorConfig] = {
        val select = quote {
            for {
                ep <- schema.eventValidators
                org <- schema.activeOrganizations(since = sinceTime) join (org => org.id == ep.orgId)
                p <- schema.validators join (p => p.id == ep.validatorId)
                dt <- schema.deviceTypes join (dt => dt.id == ep.deviceTypeId)
            }
                yield ValidatorConfig(p.name, p.version, org.shortName, dt.devType)
        }

        dsl run select
    }

    def mapperPreferences(sinceTime: LocalDateTime): List[MapperConfig] = {
        val select = quote {
            for {
                ep <- schema.eventMappers
                org <- schema.activeOrganizations(since = sinceTime) join (org => org.id == ep.orgId)
                p <- schema.mappers join (p => p.id == ep.mapperId)
                dt <- schema.deviceTypes join (dt => dt.id == ep.deviceTypeId)
            }
                yield MapperConfig(p.name, p.version, org.shortName, dt.devType)
        }

        dsl run select
    }

    private def default = new Array[Preference](3)

    private def transformer(arr: Array[Preference], mapping: Mapping): Array[Preference] = {
        mapping match {
            case m: ParserConfig => arr(0) = Preference(m.parserName, m.parserVersion)
            case v: ValidatorConfig => arr(1) = Preference(v.validatorName, v.validatorVersion)
            case n: MapperConfig => arr(2) = Preference(n.mapperName, n.mapperVersion)
        }
        arr
    }

    def transformationPreferences: TransformationPreferences = {
        val now = LocalDateTime.now()
        parserPreferences(now)
            .union(validatorPreferences(now))
            .union(mapperPreferences(now))
            .groupBy(_.organization)
            .map(grp => {
                val devTypes = grp._2
                    .groupBy(_.devType)
                    .map(dt => {
                        val devTypePref = dt._2
                            .foldLeft(default)(transformer) match {
                            case Array(pm, vm, nm) => TransformationPreference(dt._1, pm, vm, nm)
                        }
                        dt._1 -> devTypePref
                    })
                (grp._1, devTypes)
            })
    }

    def fetchDevTypeToVendorMapping: Map[String, DeviceVendor] = {
        val select = quote {
            for {
                dt <- schema.deviceTypes
                dv <- schema.vendors.join(dv => dt.vendorId == dv.id)
            } yield DeviceVendor(dt.devType, dv.name, dt.product, dt.version)
        }

        (dsl run select).map(x => x.devType -> x).toMap
    }

    def ipGeoCity(): Array[IpGeoInfo] = {
        debug("load city geo info", {
            implicit val _ = encodeNetworkArray

            val select = quote {
                for {
                    igi <- schema.ipGeoInfoCity
                } yield igi
            }

            (dsl run select).toArray
        })
    }

    def ipGeoCountry(): Array[IpGeoInfoCountry] = {
        debug("load country geo info", {
            implicit val _ = encodeNetworkArray

            val select = quote {
                for {
                    igi <- schema.ipGeoInfoCountry
                } yield igi
            }

            (dsl run select).toArray
        })
    }

    def rules(): List[Rule] = {
        val schedules: Map[Int, List[Schedule]] = schedule().groupBy(_.groupId)
        val orgs: Map[Index, Organization] = organizations().map(o => o.id -> o).toMap

        loadRules().map { case (((((rule, sadapter), source), destination), scheduleGroup), obj) =>
            val sg = scheduleGroup.scheduleGroup(schedules.getOrElse(scheduleGroup.id, List.empty))
            rule.rule(sadapter.subject(orgs(sadapter.orgId)), source, destination, sg, obj)
        }
    }

    private def loadRules(): List[(((((RuleAdapter, SubjectAdapter), Option[Host]), Option[Host]), ScheduleGroupAdapter), Option[RuleObject])] = {
        val select = quote {
            schema.rules
                .join(schema.subject)
                .on((rule, subject) => rule.subject == subject.id)
                .leftJoin(schema.hosts)
                .on { case ((rule, _), source) =>
                    rule.source.contains(source.id)
                }.leftJoin(schema.hosts)
                .on { case (((rule, _), _), destination) =>
                    rule.destination.contains(destination.id)
                }
                .join(schema.scheduleGroups)
                .on { case ((((rule, _), _), _), sg) =>
                    rule.schedule == sg.id
                }
                .leftJoin(schema.objects)
                .on { case (((((rule, _), _), _), _), ro) =>
                    rule.`object`.contains(ro.id)
                }
        }

        dsl run select
    }

    def logins(): List[LoginWithOrg] = {
        val select = quote {
            for {
                login <- schema.subject
                org <- schema.organizations.join(o => login.orgId == o.id)
            } yield LoginWithOrg(login.login,
                org.shortName,
                login.userName,
                login.orgId,
                login.phone,
                login.email,
                login.monitored,
                login.userDomain,
                login.startWork)
        }

        dsl run select
    }

    def schedule(): List[Schedule] = {
        val select = quote {
            for {
                sch <- schema.schedule
            } yield sch
        }

        dsl run select
    }

    def organizations(): List[Organization] = {
        val select = quote {
            for {
                sch <- schema.organizations
            } yield sch
        }

        dsl run select
    }

    def scripts(): List[PyScript] = {
        val select = quote {
            for {
                script <- schema.scripts
            } yield script
        }

        dsl run select
    }

    private def debug[T](name: String, action: => T): T = {
        logger.debug(s"$name: begin")
        val result = action
        logger.debug(s"$name: end")
        result
    }
}
