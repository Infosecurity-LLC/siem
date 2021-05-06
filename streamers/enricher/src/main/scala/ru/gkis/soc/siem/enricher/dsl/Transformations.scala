package ru.gkis.soc.siem.enricher.dsl

object Transformations extends Serializable
    with GeoIpEnricher
    with EventReader
    with Sender
    with ScheduleEnricher
    with WindowsLogonEnricher
    with Splitter
    with StatisticsCollector
    with WindowsObjectEnricher
    with VpnLogonEnricher
    with FirewallConnectionEnricher
