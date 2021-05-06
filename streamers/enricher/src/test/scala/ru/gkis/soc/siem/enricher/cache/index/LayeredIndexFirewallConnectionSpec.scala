package ru.gkis.soc.siem.enricher.cache.index

import org.scalatest.{FlatSpec, Matchers}
import ru.gkis.soc.siem.enricher.controls.FirewallConnectionControl
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.model.{CollectorInfo, InteractingAssetLocation, InteractionDescription, SocEvent}
import ru.gkis.soc.siem.model.access.{Allowed, Undefined, WindowsObject}
import com.google.common.collect.{Range => NumericRange}
import org.junit.runner.RunWith
import org.scalatestplus.junit.JUnitRunner

import scala.util.Random

@RunWith(classOf[JUnitRunner])
class LayeredIndexFirewallConnectionSpec extends FlatSpec with Matchers {

    // times in seconds
    private val sgForever = ScheduleGroup(Set(Schedule(0, 86399, 7, 0, isCalendar = true)))
    private val pk = ProductionCalendar(Set.empty)
    private val rules: List[Rule[NumericRange[Integer], NumericRange[Integer]]] = {
        // this control has two states: Unknown or Allowed. Restricted is never used ===================================
        val r0 = Rule[NumericRange[Integer], NumericRange[Integer]](
            id = 0,
            tp = WindowsObject,
            subj = Subject("org1", None, 0L, sgForever, None),
            obj = Some(Object(TProtocol, Some("tcp"), None, None)),
            source = Some(Location(None, Some("192.168.55.66"))),
            destination = Some(Location(None, Some("192.168.114.115"))),
            schedule = sgForever,
            aux1 = None,
            aux2 = Some(Aux(Set(NumericRange.singleton(22), NumericRange.closed(1080, 8080)))),
            result = Allowed
        )

        val r1 = Rule[NumericRange[Integer], NumericRange[Integer]](
            id = 1,
            tp = WindowsObject,
            subj = Subject("org1", None, 0L, sgForever, None),
            obj = Some(Object(TProtocol, Some("tcp"), None, None)),
            source = Some(Location(None, Some("192.168.77.88"))),
            destination = Some(Location(None, Some("192.168.114.115"))),
            schedule = sgForever,
            aux1 = Some(Aux(Set(NumericRange.singleton(22589)))),
            aux2 = Some(Aux(Set(NumericRange.singleton(22), NumericRange.closed(1080, 8080)))),
            result = Allowed
        )

        val r2 = Rule[NumericRange[Integer], NumericRange[Integer]](
            id = 2,
            tp = WindowsObject,
            subj = Subject("org1", None, 0L, sgForever, None),
            obj = Some(Object(TProtocol, None, None, None)),
            source = Some(Location(None, Some("192.168.33.44"))),
            destination = Some(Location(None, Some("192.168.114.115"))),
            schedule = sgForever,
            aux1 = None,
            aux2 = Some(Aux(Set(NumericRange.singleton(6669)))),
            result = Allowed
        )

        List(r0, r1, r2)
    }

    private val tree = FirewallConnectionControl(rules)

    "192.168.55.66" should "be able to connect port 22 at 192.168.114.115 from any port" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            source = Some(InteractingAssetLocation(hostname = Some("192.168.55.66"), port = Some(35476))),
            destination = Some(InteractingAssetLocation(hostname = Some("192.168.114.115"), port = Some(22))),
            interaction = Some(InteractionDescription(protocol = Some("TCP")))
        )
        val res = tree.search(FirewallConnectionControl.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(0))
        FirewallConnectionControl.check(tree, evt, pk) shouldBe Allowed
    }

    "192.168.55.66" should "be able to connect to any port in range [1080, 8080] at 192.168.114.115 from any port" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            source = Some(InteractingAssetLocation(hostname = Some("192.168.55.66"), port = Some(12656))),
            destination = Some(InteractingAssetLocation(hostname = Some("192.168.114.115"), port = Some(Random.nextInt(7000) + 1080))),
            interaction = Some(InteractionDescription(protocol = Some("TCP")))
        )
        val res = tree.search(FirewallConnectionControl.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(0))
        FirewallConnectionControl.check(tree, evt, pk) shouldBe Allowed
    }

    "192.168.55.66" should "not be able to connect to any port outside permitted ranges at 192.168.114.115 from any port" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            source = Some(InteractingAssetLocation(hostname = Some("192.168.55.66"), port = Some(31445))),
            destination = Some(InteractingAssetLocation(hostname = Some("192.168.114.115"), port = Some(Random.nextInt(7000) + 8081))),
            interaction = Some(InteractionDescription(protocol = Some("TCP")))
        )
        val res = tree.search(FirewallConnectionControl.decisionPath(evt))
        res.map(_.size) shouldBe None
        FirewallConnectionControl.check(tree, evt, pk) shouldBe Undefined
    }

    "192.168.11.22" should "not be able to connect port 22 at 192.168.114.115 from any port" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            source = Some(InteractingAssetLocation(hostname = Some("192.168.11.22"), port = Some(13432))),
            destination = Some(InteractingAssetLocation(hostname = Some("192.168.114.115"), port = Some(22))),
            interaction = Some(InteractionDescription(protocol = Some("TCP")))
        )
        val res = tree.search(FirewallConnectionControl.decisionPath(evt))
        res.map(_.size) shouldBe None
        FirewallConnectionControl.check(tree, evt, pk) shouldBe Undefined
    }

    "192.168.77.88" should "be able to connect port 22 at 192.168.114.115 from port 22589" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            source = Some(InteractingAssetLocation(hostname = Some("192.168.77.88"), port = Some(22589))),
            destination = Some(InteractingAssetLocation(hostname = Some("192.168.114.115"), port = Some(22))),
            interaction = Some(InteractionDescription(protocol = Some("TCP")))
        )
        val res = tree.search(FirewallConnectionControl.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(1))
        FirewallConnectionControl.check(tree, evt, pk) shouldBe Allowed
    }

    "192.168.77.88" should "not be able to connect port 22 at 192.168.114.115 from any port except 22589" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            source = Some(InteractingAssetLocation(hostname = Some("192.168.77.88"), port = Some(23456))),
            destination = Some(InteractingAssetLocation(hostname = Some("192.168.114.115"), port = Some(22))),
            interaction = Some(InteractionDescription(protocol = Some("TCP")))
        )
        val res = tree.search(FirewallConnectionControl.decisionPath(evt))
        res.map(_.size) shouldBe None
        FirewallConnectionControl.check(tree, evt, pk) shouldBe Undefined
    }

    "192.168.77.88" should "not be able to connect to any port outside permitted ranges at 192.168.114.115 from port 22589" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            source = Some(InteractingAssetLocation(hostname = Some("192.168.77.88"), port = Some(31445))),
            destination = Some(InteractingAssetLocation(hostname = Some("192.168.114.115"), port = Some(Random.nextInt(7000) + 8081))),
            interaction = Some(InteractionDescription(protocol = Some("TCP")))
        )
        val res = tree.search(FirewallConnectionControl.decisionPath(evt))
        res.map(_.size) shouldBe None
        FirewallConnectionControl.check(tree, evt, pk) shouldBe Undefined
    }

    "192.168.55.66" should "not be able to connect port 22 at 192.168.114.115 from any port without protocol" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            source = Some(InteractingAssetLocation(hostname = Some("192.168.55.66"), port = Some(35476))),
            destination = Some(InteractingAssetLocation(hostname = Some("192.168.114.115"), port = Some(22)))
        )
        val res = tree.search(FirewallConnectionControl.decisionPath(evt))
        res.map(_.size) shouldBe None
        FirewallConnectionControl.check(tree, evt, pk) shouldBe Undefined
    }

    "192.168.55.66" should "not be able to connect port 22 at 192.168.114.115 from any port by UDP" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            source = Some(InteractingAssetLocation(hostname = Some("192.168.55.66"), port = Some(35476))),
            destination = Some(InteractingAssetLocation(hostname = Some("192.168.114.115"), port = Some(22))),
            interaction = Some(InteractionDescription(protocol = Some("UDP")))
        )
        val res = tree.search(FirewallConnectionControl.decisionPath(evt))
        res.map(_.size) shouldBe None
        FirewallConnectionControl.check(tree, evt, pk) shouldBe Undefined
    }

    "192.168.33.44" should "be able to connect port 22 at 192.168.114.115 from any port by TCP" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            source = Some(InteractingAssetLocation(hostname = Some("192.168.33.44"), port = Some(35476))),
            destination = Some(InteractingAssetLocation(hostname = Some("192.168.114.115"), port = Some(6669))),
            interaction = Some(InteractionDescription(protocol = Some("TCP")))
        )
        val res = tree.search(FirewallConnectionControl.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(2))
        FirewallConnectionControl.check(tree, evt, pk) shouldBe Allowed
    }

    "192.168.33.44" should "be able to connect port 22 at 192.168.114.115 from any port by UDP" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            source = Some(InteractingAssetLocation(hostname = Some("192.168.33.44"), port = Some(35476))),
            destination = Some(InteractingAssetLocation(hostname = Some("192.168.114.115"), port = Some(6669))),
            interaction = Some(InteractionDescription(protocol = Some("TCP")))
        )
        val res = tree.search(FirewallConnectionControl.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(2))
        FirewallConnectionControl.check(tree, evt, pk) shouldBe Allowed
    }

    "192.168.33.44" should "be able to connect port 22 at 192.168.114.115 from any port even if protocol is unknown" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            source = Some(InteractingAssetLocation(hostname = Some("192.168.33.44"), port = Some(35476))),
            destination = Some(InteractingAssetLocation(hostname = Some("192.168.114.115"), port = Some(6669)))
        )
        val res = tree.search(FirewallConnectionControl.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(2))
        FirewallConnectionControl.check(tree, evt, pk) shouldBe Allowed
    }

}
