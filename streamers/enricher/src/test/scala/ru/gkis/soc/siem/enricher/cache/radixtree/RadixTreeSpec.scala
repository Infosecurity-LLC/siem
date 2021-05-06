package ru.gkis.soc.siem.enricher.cache.radixtree

import com.google.common.net.InetAddresses
import org.junit.runner.RunWith
import org.scalatest.{FlatSpec, Matchers}
import org.scalatestplus.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class RadixTreeSpec extends FlatSpec with Matchers {
    "RadixTree" should "work with IPv4" in {
        val tr: IPv4RadixTree = new IPv4RadixTree()
        tr.put("10.0.0.0/24", 42)
        tr.put("10.0.0.0/8", 69)
        tr.put("10.0.3.0/24", 123)
        tr.put("127.0.0.1/32", 2222)

        // => 69, as 10.32.32.32 belongs to 10.0.0.0/8
        tr.selectValue("10.32.32.32") should be(69)
        // => 42, as 10.0.0.32 belongs to 10.0.0.0/24
        tr.selectValue("10.0.0.32") should be(42)
        // => 123, as 10.0.3.5 belongs to 10.0.3.0/24
        tr.selectValue("10.0.3.5") should be(123)
        tr.selectValue("127.0.0.1") should be(2222)
    }

    "RadixTree" should "work with IPv6" in {
        val tr: IPv6RadixTree = new IPv6RadixTree()
        tr.put("aa:0:10:0:0:0:10:0/126", 12345)
        tr.put("bbbb::10:0/127", 12346)
        tr.put("cc:0:10:10:0:0:10:0/128", 12347)
        tr.put("fd00::/8", 5643)
        tr.put("::1/128", 2222)

        // => new BigInteger("12345"))  belongs to aa:0:10:0:0:0:10:0/126
        tr.selectValue("aa:0:10:0:0:0:10:0") should be(12345)
        // => new BigInteger("12346")) belongs to bbbb::10:0/127
        tr.selectValue("bbbb::10:0") should be(12346)
        // => new BigInteger("12347")) belongs to cc:0:10:10:0:0:10:0/128
        tr.selectValue("cc:0:10:10:0:0:10:0") should be(12347)
        tr.selectValue("fd00:0:0:0:0:0:0:0") should be(5643)
        tr.selectValue("::1") should be(2222)
    }

    "RichRadixTree" should "correct work with RadixTree" in {
        import ru.gkis.soc.siem.enricher.cache.radixtree.RichRadixTree._

        val v6: IPv6RadixTree = new IPv6RadixTree()
        v6.put("cc:0:10:10:0:0:10:0/128", 12347)

        // => new BigInteger("12347")) belongs to cc:0:10:10:0:0:10:0/128
        v6.find("cc:0:10:10:0:0:10:0") should be(Some(12347))
        v6.find("fd00:0:0:0:0:0:0:0") should be(None)


        val v4: IPv4RadixTree = new IPv4RadixTree()
        v4.put("10.0.0.0/8", 69)

        // => 69, as 10.32.32.32 belongs to 10.0.0.0/8
        v4.find("10.32.32.32") should be(Some(69))
        v4.find("192.0.3.5") should be(None)
    }

    "RichRadixTree" should "correct work with InetAddresses" in {
        import ru.gkis.soc.siem.enricher.cache.radixtree.RichRadixTree._

        val v6: IPv6RadixTree = new IPv6RadixTree()
        v6.put("cc:0:10:10:0:0:10:0/128", 12347)

        // => new BigInteger("12347")) belongs to cc:0:10:10:0:0:10:0/128
        v6.find(InetAddresses.forString("cc:0:10:10:0:0:10:0")) should be(Some(12347))
        v6.find(InetAddresses.forString("fd00:0:0:0:0:0:0:0")) should be(None)

        val v4: IPv4RadixTree = new IPv4RadixTree()
        v4.put("10.0.0.0/8", 69)

        // => 69, as 10.32.32.32 belongs to 10.0.0.0/8
        v4.find(InetAddresses.forString("10.32.32.32")) should be(Some(69))
        v4.find(InetAddresses.forString("192.0.3.5")) should be(None)
    }

    "RadixTree" should "correct work in empty state" in {
        import ru.gkis.soc.siem.enricher.cache.radixtree.RichRadixTree._

        val v6: IPv6RadixTree = new IPv6RadixTree(1)

        v6.find("cc:0:10:10:0:0:10:0") should be(None)
        v6.find(InetAddresses.forString("fd00:0:0:0:0:0:0:0")) should be(None)

        val v4: IPv4RadixTree = new IPv4RadixTree(1)

        v4.find("10.32.32.32") should be(None)
        v4.find(InetAddresses.forString("192.0.3.5")) should be(None)
    }
}