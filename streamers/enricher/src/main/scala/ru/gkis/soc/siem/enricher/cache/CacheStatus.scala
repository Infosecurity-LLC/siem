package ru.gkis.soc.siem.enricher.cache

trait CacheStatus {
    def size: Long
    def lastUpdated: Long
}
