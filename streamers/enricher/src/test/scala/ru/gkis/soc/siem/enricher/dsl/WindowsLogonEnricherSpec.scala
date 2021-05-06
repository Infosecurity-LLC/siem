package ru.gkis.soc.siem.enricher.dsl

import org.apache.spark.rdd.RDD
import org.apache.spark.streaming.{Seconds, StreamingContext}
import org.junit.runner.RunWith
import org.scalatest.{Matchers, WordSpec}
import org.scalatestplus.junit.JUnitRunner
import ru.gkis.soc.siem.enricher.cache.decisiontree._
import ru.gkis.soc.siem.enricher.controls.WindowsLogonControl
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.io.spark.EditableBroadcast
import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.model.access.{Allowed, WindowsLogon}
import ru.gkis.soc.siem.spark.SharedSparkContext

@RunWith(classOf[JUnitRunner])
class WindowsLogonEnricherSpec extends WordSpec with Matchers with SharedSparkContext with Serializable {
    "WindowsLogonEnricher" should {
        "correct work" in new setup {

            import WindowsLogonEnricher._

            lazy val event: SocEvent = defaultEvent
            val enriched: Array[SocEvent] =
                rdd
                    .enrichWindowsLogon(treeCache, pkDT)
                    .collect()

            enriched.headOption should not be empty
            val resultEvent = enriched.head
            resultEvent.getSubject.getEnrichment.isHostAccessTimeAllowed should be(Some(true))
        }
    }

    @transient
    trait setup {
        def event: SocEvent

        lazy val events: Seq[SocEvent] = Seq(event)
        lazy val rdd: RDD[SocEvent] = sc.parallelize(events, 1)
        lazy val ctx = new StreamingContext(sc, Seconds(15))

        // event cleaning:
        // _ => .
        // (.*) (=) (.*) => _.$1 := "$3",
        val defaultEvent: SocEvent = SocEvent().update(
            _.id := "4f478361184485f0b27674102ac2ddc132a489bf",
            _.eventTime := 1611220095,
            _.eventSource.location.host := "10.11.12.13",
            _.eventSource.location.hostname := "somewhere.soc.org1.corp",
            _.eventSource.location.ip := "10.11.12.13",
            _.eventSource.category := EventSourceCategory.OperatingSystem,
            _.eventSource.id := "in.msvistalog.evt.security2",
            _.eventSource.subsys := "Security",
            _.eventSource.title := "Windows 2008",
            _.eventSource.vendor := "Microsoft",
            _.source.host := "10.20.30.40",
            _.source.hostname := "DD-FF-DFSDFVDFV",
            _.source.ip := "10.20.30.40",
            _.source.nat.port := 0,
            _.source.port := 51487,
            _.source.enrichment.isNetworkLocal := true,
            _.destination.host := "10.11.12.13",
            _.destination.hostname := "somewhere",
            _.destination.ip := "10.11.12.13",
            _.destination.nat.port := 0,
            _.destination.port := 0,
            _.interaction.action := InteractionCategory.login,
            _.interaction.duration := 0,
            _.interaction.importance := ImportanceLevel.LOW,
            _.interaction.logonType := 10,
            _.interaction.startTime := 0,
            _.interaction.status := InteractionStatus.success,
            _.subject.category := Counterpart.account,
            _.subject.domain := "SOC",
            _.subject.name := "somebody",
            _.`object`.category := Counterpart.host,
            _.collector.location.host := "10.11.12.13",
            _.collector.location.hostname := "somewhere.soc.org1.corp",
            _.collector.location.ip := "10.11.12.13",
            _.collector.inputId := "in.msvistalog.evt.security2",
            _.collector.organization := "soc",
            _.data.aux1 := "DD-FF-DFSDFVDFV$",
            _.data.aux2 := "SOC",
            _.data.aux3 := "S-1-5-18",
            _.data.msgId := "4624",
            _.data.originTime := 1611133084,
            _.data.time := 1611133100
        )

        private val sgNormal = ScheduleGroup(Set(Schedule(32400, 64800, 5, 2, isCalendar = true)))

        val rule: Rule[Int, String] = Rule[Int, String](
            id = 9,
            tp = WindowsLogon,
            subj = Subject("soc", Some("somebody"), 0L, sgNormal, Some("soc")),
            obj = None,
            source = None,
            destination = Some(Location(hostname = Some("somewhere"), ip = Some("10.11.12.13"))),
            schedule = sgNormal,
            aux1 = Some(Aux[Int](Set(3, 10))),
            aux2 = None,
            result = Allowed
        )

        val tree = {
            val result = new DecisionTree[Int, String]
            result.addAll(WindowsLogonControl[Int, String](List(rule)))
            result
        }

        lazy val treeCache: EditableBroadcast[DecisionTree[Int, String]] = {
            import scala.concurrent.duration._

            new EditableBroadcast(ctx, tree, period = 60.seconds)
        }

        lazy val pkDT: EditableBroadcast[ProductionCalendar] = {
            import scala.concurrent.duration._

            new EditableBroadcast(ctx, ProductionCalendar.read("/calendar.json"), period = 10.minutes)
        }
    }

}
