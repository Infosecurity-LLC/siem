package ru.gkis.soc.siem.enricher

import com.typesafe.scalalogging.LazyLogging
import org.apache.spark.SparkConf
import org.apache.spark.broadcast.Broadcast
import org.apache.spark.metrics.source.{EnricherMetrics, MetricsAgent}
import org.apache.spark.streaming.kafka010.ConsumerStrategies.Subscribe
import org.apache.spark.streaming.kafka010.{CanCommitOffsets, HasOffsetRanges, KafkaUtils, LocationStrategies}
import org.apache.spark.streaming.{Seconds, StreamingContext}
import ru.gkis.soc.siem.cache.{CacheConfig, MetaCache}
import ru.gkis.soc.siem.commons.BaseConfig
import ru.gkis.soc.siem.enricher.cache.index.LayeredIndex
import ru.gkis.soc.siem.enricher.cache.{IpGeoInfoCache, LoginsCache, ScheduleCache}
import ru.gkis.soc.siem.enricher.controls.{FirewallConnectionControl, VpnLogonControl2, WindowsLogonControl2, WindowsObjectControl2}
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.io.kafka.{KafkaInputConfig, KafkaOutputConfig}
import ru.gkis.soc.siem.io.spark.EditableBroadcast
import com.google.common.collect.{Range => NumericRange}

object Main extends LazyLogging {

    def main(args: Array[String]): Unit = {
        import ru.gkis.soc.siem.enricher.dsl.Transformations._

        val conf = new BaseConfig with EnricherConfig with CacheConfig with KafkaInputConfig with KafkaOutputConfig
        val sparkConf = new SparkConf().setAll(conf.sparkProperties)

        val ctx = StreamingContext.getOrCreate(s"checkpoint/${conf.applicationName}",
            () => new StreamingContext(sparkConf, Seconds(conf.streamingBatchDuration)))
        val stream = KafkaUtils.createDirectStream[String, Array[Byte]](
            ctx,
            LocationStrategies.PreferConsistent,
            Subscribe[String, Array[Byte]](conf.kafkaInputTopics, conf.kafkaInputProperties)
        )

        val clientMetrics = MetricsAgent.inception(new EnricherMetrics(_, conf.metricSystemNamespace))

        val meta: MetaCache = new MetaCache(conf)
        val ipGeoInfoCache = IpGeoInfoCache(meta.ipGeoCity(), meta.ipGeoCountry())
        val geoCache = new EditableBroadcast(ctx, ipGeoInfoCache, period = conf.geoIpCacheUpdateInterval)
        val scheduleCache = new EditableBroadcast(ctx, ScheduleCache(meta.schedule()), period = conf.scheduleCacheUpdateInterval)
        val loginsCache = new EditableBroadcast(ctx, LoginsCache(meta.logins()), period = conf.loginsCacheUpdateInterval)

        val srcRules = meta.rules()
        val productionCaledar: EditableBroadcast[ProductionCalendar] =
            new EditableBroadcast(ctx, ProductionCalendar.read("/calendar.json"), period = conf.proizvodstvennyyKalendarUpdateInterval)
        val windowsLogonIndex: EditableBroadcast[LayeredIndex[Int, Nothing]] =
            new EditableBroadcast(ctx, WindowsLogonControl2(WindowsLogonControl2.convertAccessRule(srcRules)), period = conf.destinationHostRulesCacheUpdateInterval)
        val windowsObjectAccessIndex: EditableBroadcast[LayeredIndex[Nothing, Nothing]] =
            new EditableBroadcast(ctx, WindowsObjectControl2(WindowsObjectControl2.convertAccessRule(srcRules)), period = conf.windowsObjectAccessRulesUpdateInterval)
        val vpnAccessIndex: EditableBroadcast[LayeredIndex[Nothing, Nothing]] =
            new EditableBroadcast(ctx, VpnLogonControl2(VpnLogonControl2.convertAccessRule(srcRules)), period = conf.vpnLogonRulesUpdateInterval)
        val firewallConnectionIndex: EditableBroadcast[LayeredIndex[NumericRange[Integer], NumericRange[Integer]]] =
            new EditableBroadcast(ctx, FirewallConnectionControl(FirewallConnectionControl.convertAccessRule(srcRules)), period = conf.firewallConnectionRulesUpdateInterval)

        val bconf: Broadcast[KafkaOutputConfig] = ctx.sparkContext.broadcast(conf)

        stream
            .foreachRDD(rdd => {
                val offsetRanges = rdd.asInstanceOf[HasOffsetRanges].offsetRanges
                updateCaches()
                logger.info(s"Starting from offsets $offsetRanges")

                val stats: Array[InternalStatistics] = rdd
                    .deserialize()
                    .enrichGeo(geoCache)
                    .enrichFirewallConnection(firewallConnectionIndex, productionCaledar)
                    .enrichWorkSchedule(scheduleCache, loginsCache)
                    .enrichWindowsLogon2(windowsLogonIndex, productionCaledar)
                    .enrichWindowsObjectAccess2(windowsObjectAccessIndex, productionCaledar)
                    .enrichVpnLogon2(vpnAccessIndex, productionCaledar)
                    .split
                    .send(bconf)
                    .summarize

                clientMetrics.updateClientStats(
                    stats = stats,
                    ipGeoCache = geoCache.value,
                    loginCache = loginsCache.value
                )
                logger.info(s"Batch final stats: ${stats.mkString("\n")}")

                logger.info(s"Committing offsets $offsetRanges")
                stream.asInstanceOf[CanCommitOffsets].commitAsync(offsetRanges)
            })

        def updateCaches(): Unit = {
            geoCache.update(IpGeoInfoCache(meta.ipGeoCity(), meta.ipGeoCountry()))
            scheduleCache.update(ScheduleCache(meta.schedule()))
            loginsCache.update(LoginsCache(meta.logins()))

            lazy val srcRules = meta.rules()
            windowsLogonIndex.update(WindowsLogonControl2(WindowsLogonControl2.convertAccessRule(srcRules)))
            windowsObjectAccessIndex.update(WindowsObjectControl2(WindowsObjectControl2.convertAccessRule(srcRules)))
            vpnAccessIndex.update(VpnLogonControl2(VpnLogonControl2.convertAccessRule(srcRules)))
            firewallConnectionIndex.update(FirewallConnectionControl(FirewallConnectionControl.convertAccessRule(srcRules)))
            // Not used now, because data loaded from resource file
            // productionCaledar.update()
        }

        ctx.start()
        ctx.awaitTermination()
    }
}
