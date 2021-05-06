package ru.gkis.soc.siem.enricher.cache

import java.net.{Inet4Address, Inet6Address}
import java.time.{Instant, LocalDateTime, ZoneOffset}

import com.google.common.net.InetAddresses
import com.typesafe.scalalogging.LazyLogging
import ru.gkis.soc.siem.enricher.cache.radixtree.{IPv4RadixTree, IPv6RadixTree}
import ru.gkis.soc.siem.model.{IpGeoInfo, IpGeoInfoCountry, IpInfo}

object IpGeoInfoCache {
    private[enricher] val privateIpv4: IPv4RadixTree = {
        val result = new IPv4RadixTree(40)
        result.put("10.0.0.0/8", 1)
        result.put("172.16.0.0/12", 1)
        result.put("192.168.0.0/16", 1)
        result.put("127.0.0.1/32", 1)
        result
    }

    private[enricher] val privateIpv6: IPv6RadixTree = {
        val result = new IPv6RadixTree(10)
        result.put("fd00::/8", 1)
        result.put("::1/128", 1)
        result
    }
}

case class IpGeoInfoCache(cities: Array[IpGeoInfo],
                          countries: Array[IpGeoInfoCountry],
                          lastUpdated: Long = Instant.now().getEpochSecond) extends LazyLogging with CacheStatus {

    import IpGeoInfoCache._
    import ru.gkis.soc.siem.enricher.cache.radixtree.RichRadixTree._

    private[this] val shift: Long = 1000000l
    val ipv4Cities: IPv4RadixTree = new IPv4RadixTree()
    val ipv4Countries: IPv4RadixTree = new IPv4RadixTree()
    val ipv6Cities: IPv6RadixTree = new IPv6RadixTree()
    val ipv6Countries: IPv6RadixTree = new IPv6RadixTree()

    // Initialize RadixTree
    logger.info(s"IpGeoInfoCache: begin init tree")
    initCities()
    initCountries()
    logger.info(s"IpGeoInfoCache: end init tree, statistic: ipv4Cities [${ipv4Cities.getAllocatedSize}/${ipv4Cities.getSize}], ipv4Countries [${ipv4Countries.getAllocatedSize}/${ipv4Countries.getSize}], ipv6Cities [${ipv6Cities.getAllocatedSize}/${ipv6Cities.getSize}], ipv6Countries [${ipv6Countries.getAllocatedSize}/${ipv6Countries.getSize}]")

    // ******************** WARNING ********************
    // Don't rewrite code below in functional way, because every .map or .zipWithIndex create full copy of collection
    // as a result we have huge memory consumption when Cache build
    def initCities(): Unit = {
        var i: Int = 0

        while (i < cities.length) {
            var j: Int = 0

            while (j < cities(i).networks.length) {
                val (rawIp, rawMask) = parse(cities(i).networks(j))

                InetAddresses.forString(rawIp) match {
                    case ip: Inet4Address =>
                        ipv4Cities.put(ip, rawMask, address(i, j))
                    case ip: Inet6Address =>
                        ipv6Cities.put(ip, rawMask, address(i, j))
                }

                j += 1
            }
            i += 1
        }
    }

    // ******************** WARNING ********************
    // Don't rewrite code below in functional way, because every .map or .zipWithIndex create full copy of collection
    // as a result we have huge memory consumption when Cache build
    def initCountries(): Unit = {
        var i: Int = 0

        while (i < countries.length) {
            var j: Int = 0

            while (j < countries(i).networks.length) {
                val (rawIp, rawMask) = parse(countries(i).networks(j))
                InetAddresses.forString(rawIp) match {
                    case ip: Inet4Address =>
                        ipv4Countries.put(ip, rawMask, address(i, j))
                    case ip: Inet6Address =>
                        ipv6Countries.put(ip, rawMask, address(i, j))
                }

                j += 1
            }

            i += 1
        }
    }

    def isLocalIp(ip: String): Boolean = {
        InetAddresses.forString(ip) match {
            case ip: Inet4Address =>
                privateIpv4.find(ip).isDefined
            case ip: Inet6Address =>
                privateIpv6.find(ip).isDefined
        }
    }

    def find(ip: String): Option[IpInfo] = {
        if (isLocalIp(ip)) {
            None
        } else {
            val (city, country) = InetAddresses.forString(ip) match {
                case ip: Inet4Address =>
                    (
                        ipv4Cities.find(ip).map { address =>
                            val (i, j) = parse(address)
                            cities(i).network(j)
                        },
                        ipv4Countries.find(ip).map { address =>
                            val (i, j) = parse(address)
                            countries(i).network(j)
                        }
                    )
                case ip: Inet6Address =>
                    (
                        ipv6Cities.find(ip).map { address =>
                            val (i, j) = parse(address)
                            cities(i).network(j)
                        },
                        ipv6Countries.find(ip).map { address =>
                            val (i, j) = parse(address)
                            countries(i).network(j)
                        }
                    )
            }

            city.orElse(country).map {
                case IpInfo(maybeCity, maybeCountry, maybeOrg, maybeOrgId, network) =>
                    IpInfo(
                        maybeCity,
                        maybeCountry.orElse(country.flatMap(_.country)),
                        maybeOrg.orElse(country.flatMap(_.org)),
                        maybeOrgId.orElse(country.flatMap(_.ordId)),
                        network
                    )
            }
        }
    }

    private[this] def parse(network: String): (String, String) = {
        val pos = network.indexOf('/')
        (network.substring(0, pos), network.substring(pos + 1))
    }

    private[this] def address(i: Int, j: Int): Long = {
        shift * (i + 1) + j
    }

    private[this] def parse(address: Long): (Int, Int) = {
        val i = address / shift
        ((i - 1).toInt, (address - i * shift).toInt)
    }

    override def size: Long = ipv4Cities.getSize + ipv6Cities.getSize + ipv4Countries.getSize + ipv6Countries.getSize
}
