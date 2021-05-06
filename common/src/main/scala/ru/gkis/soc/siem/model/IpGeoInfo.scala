package ru.gkis.soc.siem.model

sealed trait IpGeoInfoBase {
    def city: Option[String]

    def country: Option[String]

    def org: Option[String]

    def orgId: Option[String]

    def networks: Array[String]

    def network(id: Int): IpInfo = {
        IpInfo(
            city,
            country,
            org,
            orgId,
            networks(id)
        )
    }
}

case class IpGeoInfoCountry(country: Option[String],
                            org: Option[String],
                            orgId: Option[String],
                            networks: Array[String]) extends IpGeoInfoBase {
    val city: Option[String] = None
}

case class IpGeoInfo(city: Option[String],
                     country: Option[String],
                     org: Option[String],
                     orgId: Option[String],
                     networks: Array[String]) extends IpGeoInfoBase


case class IpInfo(city: Option[String],
                  country: Option[String],
                  org: Option[String],
                  ordId: Option[String],
                  network: String)