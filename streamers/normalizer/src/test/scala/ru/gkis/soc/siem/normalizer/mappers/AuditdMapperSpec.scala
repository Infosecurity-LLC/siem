package ru.gkis.soc.siem.normalizer.mappers

import org.junit.runner.RunWith
import org.scalatest.{Matchers, WordSpec}
import org.scalatestplus.junit.JUnitRunner
import ru.gkis.soc.siem.model.{Counterpart, DeviceVendor, InteractionCategory, InteractionStatus, ParsedLog, SocEvent}
import ru.gkis.soc.siem.normalizer.{InternalSocEvent, ParsedEvent, ParsedMessage}
import ru.gkis.soc.siem.normalizer.parsers.AuditdParser
import ru.gkis.soc.siem.normalizer.validators.AuditdValidator

import java.time.{ZoneOffset, ZonedDateTime}

@RunWith(classOf[JUnitRunner])
class AuditdMapperSpec extends WordSpec with Matchers {
    "AuditdMapper" when {
        "ADD_GROUP" should {
            "correct map" in new setup {
                override def raw: String = """node=centos6 type=ADD_GROUP msg=audit(1446026204.056:543): user pid=1336 uid=0 auid=0 ses=3 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=adding group to /etc/group id=504 exe="/usr/sbin/groupadd" hostname=? addr=192.168.0.1 terminal=pts/0 res=success'"""

                result.getObject.getId shouldBe "504"
                result.getObject.category shouldBe Counterpart.userGroup

                result.getInteraction.action shouldBe InteractionCategory.create
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.originTime shouldBe 1446026204L
                result.getData.getMsgId shouldBe "ADD_GROUP"
                result.getData.getAux1 shouldBe "0"
                result.getData.getAux2 shouldBe "1336"
                result.getData.getAux4 shouldBe "3"
                result.getData.getAux5 shouldBe "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
                result.getData.getAux6 shouldBe "/usr/sbin/groupadd"
                result.getData.getAux7 shouldBe "pts/0"
            }
        }

        "ADD_USER" should {
            "correct map" in new setup {
                override def raw: String = """node=centos6 type=ADD_USER msg=audit(1446026454.514:579): user pid=1340 uid=0 auid=0 ses=3 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=adding user id=503 exe="/usr/sbin/useradd" hostname=? addr=? terminal=pts/0 res=success'"""

                result.getObject.getId shouldBe "503"
                result.getObject.category shouldBe Counterpart.account

                result.getInteraction.action shouldBe InteractionCategory.create
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getMsgId shouldBe "ADD_USER"
                result.getData.getAux2 shouldBe "1340"
                result.getData.getAux4 shouldBe "3"
                result.getData.getAux5 shouldBe "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
                result.getData.getAux6 shouldBe "/usr/sbin/useradd"
                result.getData.getAux7 shouldBe "pts/0"
            }
        }

        "DEL_GROUP" should {
            "correct map" in new setup {
                override def raw: String = """node=centos6 type=DEL_GROUP msg=audit(1446027113.674:759): user pid=1449 uid=0 auid=0 ses=3 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=removing group from /etc/group id=506 exe="/usr/sbin/groupdel" hostname=? addr=? terminal=pts/0 res=success'"""

                result.getObject.getId shouldBe "506"
                result.getObject.category shouldBe Counterpart.userGroup

                result.getInteraction.action shouldBe InteractionCategory.remove
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getMsgId shouldBe "DEL_GROUP"
                result.getData.getAux2 shouldBe "1449"
                result.getData.getAux4 shouldBe "3"
                result.getData.getAux5 shouldBe "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
                result.getData.getAux6 shouldBe "/usr/sbin/groupdel"
                result.getData.getAux7 shouldBe "pts/0"
            }
        }

        "DEL_USER" should {
            "correct map" in new setup {
                override def raw: String = """node=centos6 type=DEL_USER msg=audit(1446027168.579:774): user pid=1454 uid=0 auid=0 ses=3 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=deleting user entries id=503 exe="/usr/sbin/userdel" hostname=? addr=? terminal=pts/0 res=success'"""

                result.getObject.getId shouldBe "503"
                result.getObject.category shouldBe Counterpart.account

                result.getInteraction.action shouldBe InteractionCategory.remove
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getMsgId shouldBe "DEL_USER"
                result.getData.getAux2 shouldBe "1454"
                result.getData.getAux4 shouldBe "3"
                result.getData.getAux5 shouldBe "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
                result.getData.getAux6 shouldBe "/usr/sbin/userdel"
                result.getData.getAux7 shouldBe "pts/0"
            }
        }

        "EXECVE" should {
            "correct map" in new setup {
                override def raw: String = """node=packer-debian-7 type=EXECVE msg=audit(1460978480.992:35): argc=3 a0="dpkg" a1="--remove" a2="/var/cache/apt/archives/apache2-mpm-prefork_2.2.22-13+deb7u4_amd64.deb""""

                result.getObject.category shouldBe Counterpart.command
                result.getObject.getName shouldBe "dpkg"
                result.getObject.getProperty shouldBe "3"
                result.getObject.getValue shouldBe "dpkg --remove /var/cache/apt/archives/apache2-mpm-prefork_2.2.22-13+deb7u4_amd64.deb"

                result.getInteraction.action shouldBe InteractionCategory.execute
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getMsgId shouldBe "EXECVE"
            }
        }

        "AVC" should {
            "correct map" in new setup {
                override def raw: String = """node=centos6 type=AVC msg=audit(1158064002.046:4): avc:  denied  { read } for  pid=2496 comm="bluez-pin" name=".gdm1K3IFT" dev=dm-0 ino=3601333 scontext=user_u:system_r:bluetooth_helper_t:s0-s0:c0 tcontext=system_u:object_r:xdm_tmp_t:s0 tclass=file"""

                result.getObject.category shouldBe Counterpart.file

                result.getInteraction.action shouldBe InteractionCategory.check
                result.getInteraction.status shouldBe InteractionStatus.failure

                result.getData.getMsgId shouldBe "AVC"
                result.getData.getAux2 shouldBe "2496"
                result.getData.getAux4 shouldBe "dm-0"
                result.getData.getAux6 shouldBe "bluez-pin"
                result.getData.getAux8 shouldBe "dev=dm-0 ino=3601333 scontext=user_u:system_r:bluetooth_helper_t:s0-s0:c0 tcontext=system_u:object_r:xdm_tmp_t:s0 tclass=file"
            }
        }

        "SERVICE_START" should {
            "correct map" in new setup {
                override def raw: String = """node=centos6 type=SERVICE_START msg=audit(1337705954.274:38): pid=0 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:init_t:s0 msg=' comm="bluetooth" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'"""

                result.getObject.category shouldBe Counterpart.process

                result.getInteraction.action shouldBe InteractionCategory.start
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getMsgId shouldBe "SERVICE_START"
                result.getData.getAux2 shouldBe "0"
                result.getData.getAux4 shouldBe "4294967295"
                result.getData.getAux5 shouldBe "system_u:system_r:init_t:s0"
                result.getData.getAux6 shouldBe "/usr/lib/systemd/systemd"
            }
        }

        "SERVICE_STOP" should {
            "correct map" in new setup {
                override def raw: String = """node=centos6 type=SERVICE_STOP msg=audit(1337705959.402:56): pid=0 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:init_t:s0 msg=' comm="sendmail" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'"""

                result.getObject.category shouldBe Counterpart.process

                result.getInteraction.action shouldBe InteractionCategory.stop
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getMsgId shouldBe "SERVICE_STOP"
                result.getData.getAux2 shouldBe "0"
                result.getData.getAux4 shouldBe "4294967295"
                result.getData.getAux5 shouldBe "system_u:system_r:init_t:s0"
                result.getData.getAux6 shouldBe "/usr/lib/systemd/systemd"
            }
        }

        "USER_AUTH" should {
            "correct map" in new setup {
                override def raw: String = """node=centos6 type=USER_AUTH msg=audit(1446022123.627:80): user pid=1187 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=PAM:authentication acct="someone" exe="/usr/sbin/sshd" hostname=test12 addr=192.168.0.1 terminal=ssh res=success'"""

                result.getSubject.getName shouldBe "someone"
                result.getSubject.category shouldBe Counterpart.account

                result.getObject.category shouldBe Counterpart.system

                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getMsgId shouldBe "USER_AUTH"
                result.getData.getAux2 shouldBe "1187"
                result.getData.getAux4 shouldBe "4294967295"
                result.getData.getAux5 shouldBe "ssh"
                result.getData.getAux6 shouldBe "/usr/sbin/sshd"
                result.getData.getAux7 shouldBe "PAM:authentication"
                result.getData.getAux8 shouldBe "system_u:system_r:sshd_t:s0-s0:c0.c1023"
            }
        }

        "USER_CHAUTHTOK" should {
            "correct map" in new setup {
                override def raw: String = """node=centos6 type=USER_CHAUTHTOK msg=audit(1446028208.085:909): user pid=1497 uid=0 auid=0 ses=3 subj=unconfined_u:unconfined_r:passwd_t:s0-s0:c0.c1023 msg='op=PAM:chauthtok acct="test123" exe="/usr/bin/passwd" hostname=? addr=? terminal=pts/0 res=success'"""

                result.getObject.category shouldBe Counterpart.account

                result.getInteraction.action shouldBe InteractionCategory.modify
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getMsgId shouldBe "USER_CHAUTHTOK"
                result.getData.getAux2 shouldBe "1497"
                result.getData.getAux4 shouldBe "3"
                result.getData.getAux5 shouldBe "unconfined_u:unconfined_r:passwd_t:s0-s0:c0.c1023"
                result.getData.getAux6 shouldBe "/usr/bin/passwd"
                result.getData.getAux7 shouldBe "pts/0"
                result.getData.getAux8 shouldBe "PAM:chauthtok"
            }
        }

        "USER_CMD" should {
            "correct map" in new setup {
                override def raw: String = """node=centos6 type=USER_CMD msg=audit(1337674890.629:128): pid=0 uid=0 auid=1000 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd="/run/media/gene/VBOXADDITIONS_4.1.14_77440" cmd="./VBoxLinuxAdditions.run" terminal=pts/1 res=success'"""

                result.getObject.category shouldBe Counterpart.command

                result.getInteraction.action shouldBe InteractionCategory.execute
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getMsgId shouldBe "USER_CMD"
                result.getData.getAux2 shouldBe "0"
                result.getData.getAux4 shouldBe "2"
                result.getData.getAux5 shouldBe "./VBoxLinuxAdditions.run"
                result.getData.getAux6 shouldBe "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
                result.getData.getAux9 shouldBe "pts/1"
                result.getData.getAux10 shouldBe "/run/media/gene/VBOXADDITIONS_4.1.14_77440"
            }
        }

        "USER_END" should {
            "correct map" in new setup {
                override def raw: String = """node=localhost.localdomain type=USER_END msg=audit(1491802564.865:795): pid=4771 uid=0 auid=1001 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:session_close grantors=pam_keyinit,pam_limits acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'"""

                result.getObject.category shouldBe Counterpart.system

                result.getInteraction.action shouldBe InteractionCategory.logout
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getMsgId shouldBe "USER_END"
                result.getData.getAux2 shouldBe "4771"
                result.getData.getAux4 shouldBe "2"
                result.getData.getAux5 shouldBe "/dev/pts/0"
                result.getData.getAux6 shouldBe "/usr/bin/sudo"
                result.getData.getAux10 shouldBe "PAM:session_close"
            }
        }

        "USER_LOGIN" should {
            "correct map" in new setup {
                override def raw: String = """node=hostname.domain type=user_login msg=audit(1607490242.497:320340): pid=14501 uid=0 auid=1001 ses=850 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=login id=1001 exe="/usr/sbin/sshd" hostname=10.20.30.40 addr=10.20.30.40 terminal=/dev/pts/0 res=success'"""

                result.getObject.category shouldBe Counterpart.system

                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getMsgId shouldBe "USER_LOGIN"
                result.getData.getAux2 shouldBe "14501"
                result.getData.getAux6 shouldBe "/usr/sbin/sshd"
                result.getData.getAux9 shouldBe "system_u:system_r:sshd_t:s0-s0:c0.c1023"
            }
        }

        "multiline" should {
            "correct map" in new setup {
                override def raw: String =
                    """node=hostname2 type=CWD msg=audit(1605166663.111:148156104):  cwd="/"
                      |node=hostname2 type=PATH msg=audit(1605166663.111:148156104): item=0 name="/dev/tty" inode=1036 dev=00:05 mode=020666 ouid=0 ogid=5 rdev=05:00 objtype=NORMAL
                      |node=hostname2 type=SYSCALL msg=audit(1605166663.111:148156104): arch=c000003e syscall=2 success=no exit=-6 a0=4a9037 a1=802 a2=6eb028 a3=7ffe2cb93930 items=1 ppid=32385 pid=32386 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="sh" exe="/usr/bin/bash" key="root_action"""".stripMargin

                result.getSubject.getId shouldBe "0"
                result.getSubject.category shouldBe Counterpart.account

                result.getObject.category shouldBe Counterpart.file
                result.getObject.getName shouldBe "sh"

                result.getInteraction.action shouldBe InteractionCategory.open
                result.getInteraction.status shouldBe InteractionStatus.failure

                result.getData.getMsgId shouldBe "SYSCALL"
                result.getData.originTime shouldBe 1605166663L
                result.getData.getAux1 shouldBe "4294967295"
                result.getData.getAux2 shouldBe "32386"
                result.getData.getAux3 shouldBe "/dev/tty"
            }
        }
    }

    lazy val parser = new AuditdParser
    lazy val mapper = new AuditdMapper
    lazy val validator = new AuditdValidator

    @transient
    trait setup {
        def raw: String

        protected val msg: ParsedMessage = ParsedMessage(
            raw = Left(raw),
            eventReceivedTime = ZonedDateTime.now(ZoneOffset.UTC),
            organization = "organization",
            chain = "",
            eventDevType = "reassembledAuditD01",
            collectorHostname = "local.com",
            collectorHostIP = "127.0.0.1",
            severityId = 0,
            severity = "unknown",
            eventHostname = None,
            eventHostIP = "127.0.0.1",
            inputId = "id"
        )

        val parsedEvent: ParsedLog = parser.parse(msg.raw)
        validator.check(ParsedEvent(msg, parsedEvent)) shouldBe List.empty

        protected val ise: InternalSocEvent = InternalSocEvent(
            message = msg,
            event = parsedEvent,
            normId = "norm_id",
            rawId = "raw_id",
            eventSourceHost = "127.0.0.1"
        )

        val result: SocEvent = mapper
            .map((Map("reassembledAuditD01" -> DeviceVendor("reassembledAuditD01", "AuditD", "GNU", "xxx")), ise))

    }

}
