package ru.gkis.soc.siem.enricher.cache.index

import org.junit.runner.RunWith
import org.scalatest.{FlatSpec, Matchers}
import org.scalatestplus.junit.JUnitRunner
import ru.gkis.soc.siem.enricher.controls.{WindowsObjectControl, WindowsObjectControl2}
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.model.access._
import scalapb.lenses.Lens

import java.time.temporal.ChronoField
import java.time.{Instant, ZoneOffset}
import scala.util.Random

@RunWith(classOf[JUnitRunner])
class LayeredIndexWindowsControlSpec extends FlatSpec with Matchers {

    // times in seconds
    private val sgNormal = ScheduleGroup(Set(Schedule(32400, 64800, 5, 2, isCalendar = true)))
    private val sgForever = ScheduleGroup(Set(Schedule(0, 86399, 5, 2, isCalendar = true)))
    private val pk = ProductionCalendar(Set.empty)
    private val rules: List[Rule[Nothing, Nothing]] = {
        // by default anyone is restricted to go anywhere ==============================================================
        val r0 = Rule[Nothing, Nothing](
            id = 0,
            tp = WindowsObject,
            subj = Subject("org1", None, 0L, sgForever, Some("soc")),
            obj = Some(Object(TFile, None, None, None)),
            source = None,
            destination = None,
            schedule = sgForever,
            aux1 = None,
            aux2 = None,
            result = Restricted
        )

        val r1 = Rule[Nothing, Nothing](
            id = 1,
            tp = WindowsObject,
            subj = Subject("org1", Some("admin"), 0L, sgForever, Some("soc")),
            obj = Some(Object(TFile, None, Some("c:\\windows\\*"), None)),
            source = Some(Location(hostname = Some("admincomp"), None)),
            destination = None,
            schedule = sgForever,
            aux1 = None,
            aux2 = None,
            result = Restricted
        )

        val r2 = Rule[Nothing, Nothing](
            id = 2,
            tp = WindowsObject,
            subj = Subject("org1", Some("admin"), 0L, sgNormal, Some("soc")),
            obj = Some(Object(TFile, None, Some("c:\\windows\\system32\\driver\\etc\\hosts"), None)),
            source = Some(Location(hostname = Some("admincomp"), None)),
            destination = None,
            schedule = sgForever,
            aux1 = None,
            aux2 = None,
            result = Allowed
        )
        val r3 = Rule[Nothing, Nothing](
            id = 3,
            tp = WindowsObject,
            subj = Subject("org1", Some("somebody"), 0L, sgNormal, Some("soc")),
            obj = Some(Object(TFile, None, Some("c:\\*"), None)),
            source = None,
            destination = None,
            schedule = sgForever,
            aux1 = None,
            aux2 = None,
            result = Allowed
        )

        val r4 = Rule[Nothing, Nothing](
            id = 4,
            tp = WindowsObject,
            subj = Subject("org1", Some("admin"), 0L, sgForever, Some("soc")),
            obj = Some(Object(TFile, None, Some("c:\\*"), None)),
            source = Some(Location(hostname = Some("admincomp"), None)),
            destination = None,
            schedule = sgForever,
            aux1 = None,
            aux2 = None,
            result = Allowed
        )

        val r5 = Rule[Nothing, Nothing](
            id = 5,
            tp = WindowsObject,
            subj = Subject("org1", Some("somebody"), 0L, sgForever, Some("soc")),
            obj = Some(Object(TFile, None, Some("sysvol"), None)),
            source = None,
            destination = None,
            schedule = sgForever,
            aux1 = None,
            aux2 = None,
            result = Allowed
        )

        List(r0, r1, r2, r3, r4, r5)
    }

    private val tree = WindowsObjectControl2(rules)
    private val treeNoDefault = WindowsObjectControl2(rules.drop(1))

    "Admin" should "be able to access any file or directory" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("SOC"))),
            destination = Some(InteractingAssetLocation(hostname = Some("admincomp"))),
            `object` = Some(ObjectInfo(category = Counterpart.file, path = Some("C:\\Program Files\\Java")))
        )
        val res = tree.search(WindowsObjectControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(4))
        WindowsObjectControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsObjectControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(4))
        WindowsObjectControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

    "Admin" should "not be able to access any files in c:\\windows" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("SOC"))),
            destination = Some(InteractingAssetLocation(hostname = Some("admincomp"))),
            `object` = Some(ObjectInfo(category = Counterpart.file, path = Some("C:\\Windows\\System32\\")))
        )
        val res = tree.search(WindowsObjectControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsObjectControl2.check(tree, evt, pk) shouldBe Restricted
        val ndres = treeNoDefault.search(WindowsObjectControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsObjectControl2.check(treeNoDefault, evt, pk) shouldBe Restricted
    }

    "Admin" should "be able to access hosts file" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("SOC"))),
            destination = Some(InteractingAssetLocation(hostname = Some("admincomp"))),
            `object` = Some(ObjectInfo(category = Counterpart.file, path = Some("C:\\Windows\\System32\\Driver\\etc\\hosts")))
        )
        val res = tree.search(WindowsObjectControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(2))
        WindowsObjectControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsObjectControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(2))
        WindowsObjectControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

    "somebody" should "be able to access to any file on c:\\ from any host" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("somebody"), domain = Some("SOC"))),
            destination = Some(InteractingAssetLocation(ip = Some("10.20.30.40"))),
            `object` = Some(ObjectInfo(category = Counterpart.file, path = Some("C:\\Windows\\System32\\Driver\\etc\\hosts")))
        )
        val res = tree.search(WindowsObjectControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(3))
        WindowsObjectControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsObjectControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(3))
        WindowsObjectControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

    "somebody" should "be NOT able to access to \\\\*\\IPC$" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("somebody"), domain = Some("SOC"))),
            destination = Some(InteractingAssetLocation(ip = Some("10.20.30.40"))),
            `object` = Some(ObjectInfo(category = Counterpart.url, name = Some("\\\\*\\IPC$")))
        )
        val res = tree.search(WindowsObjectControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(0))
        WindowsObjectControl2.check(tree, evt, pk) shouldBe Restricted
        val ndres = treeNoDefault.search(WindowsObjectControl2.decisionPath(evt))
        ndres.map(_.map(_.id)) shouldBe None
        WindowsObjectControl2.check(treeNoDefault, evt, pk) shouldBe Undefined
    }

    "somebody" should "be able to access to \\\\*\\SYSVOL" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("somebody"), domain = Some("SOC"))),
            destination = Some(InteractingAssetLocation(ip = Some("10.20.30.40"))),
            `object` = Some(ObjectInfo(category = Counterpart.url, name = Some("\\\\*\\SYSVOL"), path = Some("\\??\\C:\\Windows\\SYSVOL\\sysvol")))
        )
        val res = tree.search(WindowsObjectControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(5))
        WindowsObjectControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsObjectControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(5))
        WindowsObjectControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

}