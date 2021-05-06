package ru.gkis.soc.siem.normalizer.validators

import java.time.ZonedDateTime

import org.junit.runner.RunWith
import org.scalatest.{FlatSpec, Matchers}
import org.scalatestplus.junit.JUnitRunner
import ru.gkis.soc.siem.normalizer.{ParsedEvent, ParsedMessage}

@RunWith(classOf[JUnitRunner])
class WindowsSecurityValidatorSpec extends FlatSpec with Matchers {
    private val msg = ParsedMessage(
                                Left("13"),
                                ZonedDateTime.now(),
                                "test",
                                "{}",
                                "windows",
                                "collector",
                                "127.0.0.1",
                                1,
                                "LOW",
                                Some("eventSource"),
                                "10.2.2.1",
                                "windows-security"
                            )

    "Logon event" should "be filtered out if logon type is 3 and username ends with $" in {
        val e = ParsedEvent(msg, Map(("EventID", "4624"), ("LogonType", "3"), ("TargetUserName", "username$")))
        val v = new WindowsSecurityValidator
        v.check(e).nonEmpty shouldBe(true)
    }

    "Logon event" should "pass filter if LogonType other than 3 and TargetUserName ends with $" in {
        val e = ParsedEvent(msg, Map(("EventID", "4624"), ("LogonType", "2"), ("TargetUserName", "username$")))
        val v = new WindowsSecurityValidator
        v.check(e).isEmpty shouldBe(true)
    }

    "Logon event" should "pass filter if TargetUserName does not end with $" in {
        val v = new WindowsSecurityValidator
        val m1 = Map(("EventID", "4624"), ("LogonType", "7"), ("TargetUserName", "username"))
        v.check(ParsedEvent(msg, m1)).isEmpty shouldBe(true)
        val m2 = Map(("EventID", "4624"), ("LogonType", "3"), ("TargetUserName", "username"))
        v.check(ParsedEvent(msg, m2)).isEmpty shouldBe(true)
    }

    "Any windows event" should "pass filter if there is no TargetUserName" in {
        val v = new WindowsSecurityValidator
        val m1 = Map(("EventID", "4728"), ("LogonType", "10"))
        v.check(ParsedEvent(msg, m1)).isEmpty shouldBe(true)
        val m2 = Map(("EventID", "4728"), ("LogonType", "3"))
        v.check(ParsedEvent(msg, m2)).isEmpty shouldBe(true)
    }

    "Any windows event" should "pass filter if there is no LogonType" in {
        val v = new WindowsSecurityValidator
        val m1 = Map(("EventID", "4801"), ("TargetUserName", "username"))
        v.check(ParsedEvent(msg, m1)).isEmpty shouldBe(true)
        val m2 = Map(("EventID", "4801"), ("TargetUserName", "username$"))
        v.check(ParsedEvent(msg, m2)).isEmpty shouldBe(true)
    }

    "Any windows event" should "pass filter if there is no TargetUserName and LogonType" in {
        val e = ParsedEvent(msg, Map(("EventID", "4764")))
        val v = new WindowsSecurityValidator
        v.check(e).isEmpty shouldBe(true)
    }

    "Windows events with unknown EventID" should "be filtered out" in {
        val e = ParsedEvent(msg, Map(("EventID", "5134")))
        val v = new WindowsSecurityValidator
        v.check(e).nonEmpty shouldBe(true)
    }

    "Windows security validator" should "not throw exception if no EventID supplied" in {
        val e = ParsedEvent(msg, Map())
        val v = new WindowsSecurityValidator
        v.check(e).nonEmpty shouldBe(true)
    }
}
