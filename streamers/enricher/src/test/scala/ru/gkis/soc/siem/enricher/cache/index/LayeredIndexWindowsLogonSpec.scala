package ru.gkis.soc.siem.enricher.cache.index

import org.junit.runner.RunWith
import org.scalatest.{FlatSpec, Matchers}
import org.scalatestplus.junit.JUnitRunner
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.model.access._
import ru.gkis.soc.siem.enricher.controls.WindowsLogonControl2

@RunWith(classOf[JUnitRunner])
class LayeredIndexWindowsLogonSpec extends FlatSpec with Matchers {

    // times in seconds
    private val sgNormal = ScheduleGroup(Set(Schedule(32400, 64800, 5, 2, isCalendar = true)))
    private val sgEvening = ScheduleGroup(Set(Schedule(64800, 86400, 5, 2, isCalendar = true)))
    private val sgForever = ScheduleGroup(Set(Schedule(0, 86400, 5, 2, isCalendar = true)))
    private val pk = ProductionCalendar(Set.empty)
    private val rules: List[Rule[Int, Nothing]] = {
        // by default anyone is restricted to go anywhere ==============================================================
        val r0 = Rule[Int, Nothing](
            id = 0,
            tp = WindowsLogon,
            subj = Subject("org1", None, 0L, sgForever, None),
            obj = None,
            source = None,
            destination = None,
            schedule = sgForever,
            aux1 = None,
            aux2 = None,
            result = Restricted
        )

        // admin can access any destination and can never access critical bloomberg host ===============================
        val r1 = Rule[Int, Nothing](
            id = 1,
            tp = WindowsLogon,
            subj = Subject("org1", Some("admin"), 0L, sgNormal, None),
            obj = None,
            source = None,
            destination = None,
            schedule = sgNormal,
            aux1 = Some(Aux[Int](Set(2, 4, 5, 6, 7, 8, 9, 10, 11))),
            aux2 = None,
            result = Allowed
        )

        val r2 = Rule[Int, Nothing](
            id = 2,
            tp = WindowsLogon,
            subj = Subject("org1", Some("admin"), 0L, sgNormal, None),
            obj = None,
            source = None,
            destination = Some(Location(Some("bloomberg"), None)), // ip 10.0.0.12
            schedule = sgForever,
            aux1 = None,
            aux2 = None,
            result = Restricted
        )

        // users can access terminal only from own host at worktime ====================================================
        val r3 = Rule[Int, Nothing](
            id = 3,
            tp = WindowsLogon,
            subj = Subject("org1", Some("user1"), 0L, sgNormal, None),
            obj = None,
            source = Some(Location(Some("usercomp1"), Some("192.168.0.20"))),
            destination = Some(Location(Some("terminal"), Some("10.0.0.11"))),
            schedule = sgForever,
            aux1 = Some(Aux[Int](Set(4, 10))),
            aux2 = None,
            result = Allowed
        )

        val r4 = Rule[Int, Nothing](
            id = 4,
            tp = WindowsLogon,
            subj = Subject("org1", Some("user2"), 0L, sgNormal, Some("org1.corp")),
            obj = None,
            source = Some(Location(Some("usercomp2"), Some("192.168.0.21"))),
            destination = Some(Location(Some("terminal"), Some("10.0.0.11"))),
            schedule = sgForever,
            aux1 = Some(Aux[Int](Set(4, 10))),
            aux2 = None,
            result = Allowed
        )

        val r5 = Rule[Int, Nothing](
            id = 5,
            tp = VpnLogon,
            subj = Subject("org1", Some("user2"), 0L, sgNormal, None),
            obj = None,
            source = Some(Location(Some("home"), Some("66.123.76.34"))),
            destination = None,
            schedule = sgNormal,
            aux1 = None,
            aux2 = None,
            result = Allowed
        )

        val r6 = Rule[Int, Nothing](
            id = 6,
            tp = WindowsLogon,
            subj = Subject("org1", Some("user2"), 0L, sgNormal, Some("org1")),
            obj = None,
            source = Some(Location(Some("usercomp2"), Some("192.168.0.21"))),
            destination = Some(Location(Some("work_terminal"), Some("10.0.0.20"))),
            schedule = sgNormal,
            aux1 = Some(Aux[Int](Set(4, 10))),
            aux2 = None,
            result = Allowed
        )

        // users can access from different domain terminal only from own host at worktime ====================================================
        val r7 = Rule[Int, Nothing](
            id = 7,
            tp = WindowsLogon,
            subj = Subject("org1", Some("user2"), 0L, sgNormal, Some("org1.corp")),
            obj = None,
            source = Some(Location(Some("usercomp2"), Some("192.168.0.21"))),
            destination = Some(Location(Some("work_terminal"), Some("10.0.0.20"))),
            schedule = sgNormal,
            aux1 = Some(Aux[Int](Set(4, 10))),
            aux2 = None,
            result = Allowed
        )

        val r8 = Rule[Int, Nothing](
            id = 8,
            tp = WindowsLogon,
            subj = Subject("org1", None, 0L, sgNormal, None),
            obj = None,
            source = None,
            destination = Some(Location(Some("test_terminal"), None)),
            schedule = sgNormal,
            aux1 = Some(Aux[Int](Set(4, 10))),
            aux2 = None,
            result = Allowed
        )

        val r9 = Rule[Int, Nothing](
            id = 9,
            tp = WindowsLogon,
            subj = Subject("org1", Some("somebody"), 0L, sgNormal, Some("soc")),
            obj = None,
            source = None,
            destination = Some(Location(hostname = Some("somewhere"), ip = Some("10.20.30.40"))),
            schedule = sgNormal,
            aux1 = Some(Aux[Int](Set(3, 10))),
            aux2 = None,
            result = Allowed
        )

        val r10 = Rule[Int, Nothing](
            id = 10,
            tp = WindowsLogon,
            subj = Subject("org1", Some("someone.dp"), 0L, sgNormal, None),
            obj = None,
            source = None,
            destination = Some(Location(Some("someone"), Some("192.168.33.44"))),
            schedule = sgNormal,
            aux1 = Some(Aux(Set(10, 2, 7))),
            aux2 = None,
            result = Allowed
        )

        val r11 = Rule[Int, Nothing](
            id = 11,
            tp = WindowsLogon,
            subj = Subject("org1", Some("someone.dp"), 0L, sgNormal, None),
            obj = None,
            source = None,
            destination = Some(Location(Some("someone"), Some("192.168.33.44"))),
            schedule = sgEvening,
            aux1 = Some(Aux(Set(2))),
            aux2 = None,
            result = Allowed
        )

        List(r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11)
    }

    private val tree = WindowsLogonControl2(rules)
    private val treeNoDefault = WindowsLogonControl2(rules.drop(1))

    "Admin" should "be able to login into any computer by hostname except bloomberg" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("admincomp"))),
            destination = Some(InteractingAssetLocation(hostname = Some("usercomp1"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

    "Admin" should "be able to login into any unknown computer by hostname except bloomberg" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("randomcomp1"))),
            destination = Some(InteractingAssetLocation(hostname = Some("randomcomp2"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

    "Admin" should "be able to login into any computer by ip except bloomberg" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("admincomp"))),
            destination = Some(InteractingAssetLocation(ip = Some("192.168.0.20"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

    "Admin" should "be able to login into any unknown computer by ip except bloomberg" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(ip = Some("1.1.1.1"))),
            destination = Some(InteractingAssetLocation(ip = Some("8.8.8.8"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

    "Admin" should "not be able to login into bloomberg by hostname" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("admincomp"))),
            destination = Some(InteractingAssetLocation(hostname = Some("bloomberg"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(2))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Restricted
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(2))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Restricted
    }

    "Admin" should "be able to login into bloomberg by ip" in {
        // cause rule has a destination with hostname only
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("admincomp"))),
            destination = Some(InteractingAssetLocation(ip = Some("10.0.0.12"))), // bloomberg
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

    "Admin" should "not be able to login into any allowed host with restricted logonType" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("admincomp"))),
            destination = Some(InteractingAssetLocation(hostname = Some("usercomp2"))),
            interaction = Some(InteractionDescription(logonType = Some(3))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Restricted
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Restricted
    }

    "Admin" should "not be able to login into any allowed ip with restricted logonType" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("admincomp"))),
            destination = Some(InteractingAssetLocation(ip = Some("192.168.0.20"))),
            interaction = Some(InteractionDescription(logonType = Some(3))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Restricted
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Restricted
    }

    "Admin" should "not be able to login into bloomberg by hostname with restricted logonType" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("admincomp"))),
            destination = Some(InteractingAssetLocation(hostname = Some("bloomberg"))),
            interaction = Some(InteractionDescription(logonType = Some(3))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(2))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Restricted
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(2))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Restricted
    }

    "Admin" should "not be able to login into bloomberg by ip with restricted logonType" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("admin"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("admincomp"))),
            destination = Some(InteractingAssetLocation(ip = Some("10.0.0.12"))), // bloomberg
            interaction = Some(InteractionDescription(logonType = Some(3))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Restricted
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(1))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Restricted
    }

    "User2" should "be able to login to a terminal by hostname from own workstation" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("user2"), domain = Some("org1.corp"))),
            source = Some(InteractingAssetLocation(hostname = Some("usercomp2"))),
            destination = Some(InteractingAssetLocation(hostname = Some("terminal"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(4))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(4))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

    "User2" should "not be able to login to a terminal by hostname from other workstations" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("user2"), domain = Some("org1.corp"))),
            source = Some(InteractingAssetLocation(hostname = Some("usercomp1"))),
            destination = Some(InteractingAssetLocation(hostname = Some("terminal"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(0))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Restricted
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.map(_.id)) shouldBe None
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Undefined
    }

    "User2" should "be able to login to a terminal by ip from own workstation" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("user2"), domain = Some("org1.corp"))),
            source = Some(InteractingAssetLocation(hostname = Some("usercomp2"))),
            destination = Some(InteractingAssetLocation(ip = Some("10.0.0.11"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(4))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(4))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

    "User2" should "not be able to login anywhere except terminal" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("user2"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("usercomp2"))),
            destination = Some(InteractingAssetLocation(hostname = Some("usercomp1"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(0))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Restricted
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.map(_.id)) shouldBe None
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Undefined
    }

    "User2" should "be able to login to a terminal at working hours" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("user2"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("usercomp2"))),
            destination = Some(InteractingAssetLocation(hostname = Some("work_terminal"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(6))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(6))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

    "Any user from organization" should "be able to login to a terminal" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("testov-test"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("usercomp2"))),
            destination = Some(InteractingAssetLocation(hostname = Some("test_terminal"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(8))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(8))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

    "User2" should "not be able to login to a terminal after hours" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("user2"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("usercomp2"))),
            destination = Some(InteractingAssetLocation(hostname = Some("work_terminal"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1603314000L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(0))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Restricted
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.map(_.id)) shouldBe None
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Undefined
    }

    "User1" should "not be able to login anywhere except own workstation with restrictedLogonType" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("user1"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("usercomp1"))),
            destination = Some(InteractingAssetLocation(hostname = Some("usercomp2"))),
            interaction = Some(InteractionDescription(logonType = Some(3))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(0))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Restricted
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.map(_.id)) shouldBe None
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Undefined
    }

    "Unknown organizations" must "be treated as Undefined" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org2")),
            subject = Some(SubjectInfo(name = Some("user2"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("usercomp2"))),
            destination = Some(InteractingAssetLocation(hostname = Some("usercomp1"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.map(_.id)) shouldBe None
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Undefined
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.map(_.id)) shouldBe None
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Undefined
    }

    "Unknown hosts" should "be restricted for users" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("user2"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("usercomp2"))),
            destination = Some(InteractingAssetLocation(hostname = Some("some_host"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(0))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Restricted
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.map(_.id)) shouldBe None
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Undefined
    }

    "All hosts" should "be restricted for unknown users" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("unknown"), domain = Some("org1"))),
            source = Some(InteractingAssetLocation(hostname = Some("terminal"))),
            destination = Some(InteractingAssetLocation(hostname = Some("usercomp1"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1613735618L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(0))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Restricted
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.map(_.id)) shouldBe None
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Undefined
    }

    "somebody" should "be able to login somewhere.soc.org1.corp" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(name = Some("somebody"), domain = Some("SOC"))),
            source = Some(InteractingAssetLocation(hostname = Some("10.26.26.96"))),
            destination = Some(InteractingAssetLocation(hostname = Some("somewhere"), ip = Some("10.20.30.40"))),
            interaction = Some(InteractionDescription(logonType = Some(10))),
            data = Some(DataPayload(originTime = 1611048174L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(9))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(9))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

    "[SOC-1315] Logon control" should "be case insensitive" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(category = Counterpart.account, name = Some("someone.dp"), domain = Some("ORG1"))),
            eventSource = Some(EventSourceInfo(title = "Windows 2008")),
            interaction = Some(InteractionDescription(logonType = Some(7), action = InteractionCategory.login)),
            `object` = Some(ObjectInfo(category = Counterpart.host)),
            source = Some(InteractingAssetLocation(host = "10.0.0.20", ip = Some("10.0.0.20"), hostname = Some("work_terminal"))),
            destination = Some(InteractingAssetLocation(host = "192.168.33.44", ip = Some("192.168.33.44"), hostname = Some("SOMEONE"))),
            data = Some(DataPayload(originTime = 1611048174L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(10))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(10))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

    "[SOC-1315] Logon control" should "use another rule for evening control" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(category = Counterpart.account, name = Some("someone.dp"), domain = Some("ORG1"))),
            eventSource = Some(EventSourceInfo(title = "Windows 2008")),
            interaction = Some(InteractionDescription(logonType = Some(2), action = InteractionCategory.login)),
            `object` = Some(ObjectInfo(category = Counterpart.host)),
            source = Some(InteractingAssetLocation(host = "10.0.0.20", ip = Some("10.0.0.20"), hostname = Some("work_terminal"))),
            destination = Some(InteractingAssetLocation(host = "192.168.33.44", ip = Some("192.168.33.44"), hostname = Some("SOMEONE"))),
            data = Some(DataPayload(originTime = 1611090000L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(11))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Allowed
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.size) shouldBe Some(1)
        ndres.map(_.map(_.id)) shouldBe Some(List(11))
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Allowed
    }

    "[SOC-1315] Logon control" should "restrict access at night time for someone.dp" in {
        val evt = SocEvent(
            collector = Some(CollectorInfo(organization = "org1")),
            subject = Some(SubjectInfo(category = Counterpart.account, name = Some("someone.dp"), domain = Some("ORG1"))),
            eventSource = Some(EventSourceInfo(title = "Windows 2008")),
            interaction = Some(InteractionDescription(logonType = Some(2), action = InteractionCategory.login)),
            `object` = Some(ObjectInfo(category = Counterpart.host)),
            source = Some(InteractingAssetLocation(host = "10.0.0.20", ip = Some("10.0.0.20"), hostname = Some("work_terminal"))),
            destination = Some(InteractingAssetLocation(host = "192.168.33.44", ip = Some("192.168.33.44"), hostname = Some("SOMEONE"))),
            data = Some(DataPayload(originTime = 1611025200L))
        )
        val res = tree.search(WindowsLogonControl2.decisionPath(evt))
        res.map(_.size) shouldBe Some(1)
        res.map(_.map(_.id)) shouldBe Some(List(0))
        WindowsLogonControl2.check(tree, evt, pk) shouldBe Restricted
        val ndres = treeNoDefault.search(WindowsLogonControl2.decisionPath(evt))
        ndres.map(_.map(_.id)) shouldBe None
        WindowsLogonControl2.check(treeNoDefault, evt, pk) shouldBe Undefined
    }

}
