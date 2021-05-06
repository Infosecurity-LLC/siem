package ru.gkis.soc.siem.enricher.cache.decisiontree

import org.junit.runner.RunWith
import org.scalatest.{FlatSpec, Matchers}
import org.scalatestplus.junit.JUnitRunner
import ru.gkis.soc.siem.enricher.controls.WindowsObjectControl
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.model.access._

import scala.util.Random

@RunWith(classOf[JUnitRunner])
class DecisionTreeWindowsControlSpec extends FlatSpec with Matchers {

    // times in seconds
    private val sgNormal = ScheduleGroup(Set(Schedule(32400, 64800, 5, 2, isCalendar = true)))
    private val sgForever = ScheduleGroup(Set(Schedule(0, 86399, 5, 2, isCalendar = true)))
    private val rules: List[Rule[Int, Nothing]] = {
        // by default anyone is restricted to go anywhere ==============================================================
        val r0 = Rule[Int, Nothing](
            id = 0,
            tp = WindowsObject,
            subj = Subject("org1", None, 0L, sgForever, Some("SOC")),
            obj = Some(Object(TFile, None, None, None)),
            source = None,
            destination = None,
            schedule = sgForever,
            aux1 = None,
            aux2 = None,
            result = Restricted
        )

        val r1 = Rule[Int, Nothing](
            id = 1,
            tp = WindowsObject,
            subj = Subject("org1", Some("admin"), 0L, sgForever, Some("SOC")),
            obj = Some(Object(TFile, None, Some("c:\\windows"), None)),
            source = Some(Location(hostname = Some("admincomp"), None)),
            destination = None,
            schedule = sgForever,
            aux1 = None,
            aux2 = None,
            result = Restricted
        )

        val r2 = Rule[Int, Nothing](
            id = 2,
            tp = WindowsObject,
            subj = Subject("org1", Some("admin"), 0L, sgNormal, Some("SOC")),
            obj = Some(Object(TFile, None, Some("c:\\windows\\system32\\driver\\etc\\hosts"), None)),
            source = Some(Location(hostname = Some("admincomp"), None)),
            destination = None,
            schedule = sgForever,
            aux1 = None,
            aux2 = None,
            result = Allowed
        )
        val r3 = Rule[Int, Nothing](
            id = 3,
            tp = WindowsObject,
            subj = Subject("org1", Some("somebody"), 0L, sgNormal, Some("SOC")),
            obj = Some(Object(TFile, None, Some("c:\\"), None)),
            source = None,
            destination = None,
            schedule = sgForever,
            aux1 = None,
            aux2 = None,
            result = Allowed
        )

        val r4 = Rule[Int, Nothing](
            id = 4,
            tp = WindowsObject,
            subj = Subject("org1", Some("admin"), 0L, sgForever, Some("SOC")),
            obj = Some(Object(TFile, None, Some("c:\\"), None)),
            source = Some(Location(hostname = Some("admincomp"), None)),
            destination = None,
            schedule = sgForever,
            aux1 = None,
            aux2 = None,
            result = Allowed
        )

        List(r0, r1, r2, r3, r4)
    }

    WindowsObjectControl[Int, Nothing](rules)
        .map(_.path.map(node => s"${node.orNull}")
            .mkString(" -> ")).foreach(System.out.println)

    private val tree = new DecisionTree[Int, Nothing]
    tree.addAll(WindowsObjectControl[Int, Nothing](rules))

    private val treeShuffled = new DecisionTree[Int, Nothing]
    private val rulesShuffled = Random.shuffle(rules)
    treeShuffled.addAll(WindowsObjectControl[Int, Nothing](rulesShuffled))

    private val treeNoDefault = new DecisionTree[Int, Nothing]
    private val rulesNoDefault = rules.drop(1)
    treeNoDefault.addAll(WindowsObjectControl[Int, Nothing](rulesNoDefault))

    private def control(t: DecisionTree[Int, Nothing], evt: SocEvent) =
        t.newControl(WindowsObjectControl.decisionPath(evt).get).check(evt, ProductionCalendar(Set.empty))

    "Admin" should "be able to access any file or directory" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("SOC"))),
            eventSource = Some(EventSourceInfo(location = Some(AssetLocation(hostname = Some("admincomp"))))),
            `object` = Some(ObjectInfo(category = Counterpart.file, path = Some("c:\\program files\\java")))
        )
        System.out.println(WindowsObjectControl.decisionPath(evt).get)
        control(tree, evt) shouldBe Allowed
        control(treeShuffled, evt) shouldBe Allowed
        control(treeNoDefault, evt) shouldBe Allowed
    }

    "Admin" should "not be able to access any files in c:\\windows" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("SOC"))),
            eventSource = Some(EventSourceInfo(location = Some(AssetLocation(hostname = Some("admincomp"))))),
            `object` = Some(ObjectInfo(category = Counterpart.file, path = Some("c:\\windows\\system32\\")))
        )
        control(tree, evt) shouldBe Restricted
        control(treeShuffled, evt) shouldBe Restricted
        control(treeNoDefault, evt) shouldBe Restricted
    }

    "Admin" should "be able to access hosts file" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("SOC"))),
            eventSource = Some(EventSourceInfo(location = Some(AssetLocation(hostname = Some("admincomp"))))),
            `object` = Some(ObjectInfo(category = Counterpart.file, path = Some("c:\\windows\\system32\\driver\\etc\\hosts")))
        )
        control(tree, evt) shouldBe Allowed
        control(treeShuffled, evt) shouldBe Allowed
        control(treeNoDefault, evt) shouldBe Allowed
    }

    "somebody" should "be able to access to any file on c:\\ from any host" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("somebody"), domain = Some("SOC"))),
            eventSource = Some(EventSourceInfo(location = Some(AssetLocation(ip = Some("10.20.30.40"))))),
            `object` = Some(ObjectInfo(category = Counterpart.file, path = Some("c:\\windows\\system32\\driver\\etc\\hosts")))
        )
        control(tree, evt) shouldBe Allowed
        control(treeShuffled, evt) shouldBe Allowed
        control(treeNoDefault, evt) shouldBe Allowed
    }

    "somebody" should "be NOT able to access to \\\\*\\IPC$" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("somebody"), domain = Some("SOC"))),
            eventSource = Some(EventSourceInfo(location = Some(AssetLocation(ip = Some("10.20.30.40"))))),
            `object` = Some(ObjectInfo(category = Counterpart.file, name = Some("\\\\*\\IPC$")))
        )
        control(tree, evt) shouldBe Restricted
        control(treeShuffled, evt) shouldBe Restricted
        control(treeNoDefault, evt) shouldBe Undefined
    }
}