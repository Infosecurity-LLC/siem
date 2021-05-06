package ru.gkis.soc.siem.normalizer.mappers.helpers

import org.junit.runner.RunWith
import org.scalatest.{Matchers, FlatSpec}
import org.scalatestplus.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class HostnameVsFqdnSpec extends FlatSpec with Matchers {

    "HostnameVsFqdn helper" should "correctly parse fqdn and hostname if both present" in {
        val (fqdn, hostname) = HostnameVsFqdn(Some("test.org1.corp"), Some("test"))
        fqdn shouldBe Some("test.org1.corp")
        hostname shouldBe Some("test")
    }

    "HostnameVsFqdn helper" should "correctly parse fqdn and hostname if both present and mixed" in {
        val (fqdn, hostname) = HostnameVsFqdn(Some("test"), Some("test.org1.corp"))
        fqdn shouldBe Some("test.org1.corp")
        hostname shouldBe Some("test")
    }

    "HostnameVsFqdn helper" should "correctly parse fqdn and hostname if no fqdn present and hostname is fqdn" in {
        val (fqdn, hostname) = HostnameVsFqdn(None, Some("test.org1.corp"))
        fqdn shouldBe Some("test.org1.corp")
        hostname shouldBe Some("test")
    }

    "HostnameVsFqdn helper" should "correctly parse fqdn and hostname if no fqdn present and hostname is hostname" in {
        val (fqdn, hostname) = HostnameVsFqdn(None, Some("test"))
        fqdn shouldBe None
        hostname shouldBe Some("test")
    }

    "HostnameVsFqdn helper" should "correctly parse fqdn and hostname if no hostname present and fqdn is fqdn" in {
        val (fqdn, hostname) = HostnameVsFqdn(Some("test.org1.corp"), None)
        fqdn shouldBe Some("test.org1.corp")
        hostname shouldBe Some("test")
    }

    "HostnameVsFqdn helper" should "correctly parse fqdn and hostname if no hostname present and fqdn is hostname" in {
        val (fqdn, hostname) = HostnameVsFqdn(Some("test"), None)
        fqdn shouldBe None
        hostname shouldBe Some("test")
    }

    "HostnameVsFqdn helper" should "correctly parse fqdn and hostname if no hostname and fqdn present" in {
        val (fqdn, hostname) = HostnameVsFqdn(None, None)
        fqdn shouldBe None
        hostname shouldBe None
    }

}
