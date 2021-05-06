package org.apache.spark.metrics.source

import com.codahale.metrics.MetricRegistry
import org.apache.spark.SparkEnv
import org.apache.spark.metrics.MetricsSystem

/**
 * This object is kinda special agent: gets metrics registry from SparkEnv and hacks it. After hacking it creates a
 * Metrics instance capable of modifying spark metrics system
 */
object MetricsAgent {

    def inception[M <: Metrics](apply: MetricRegistry => M): M = {
        val system: MetricsSystem = SparkEnv.get.metricsSystem
        val registry = classOf[MetricsSystem].getDeclaredField("org$apache$spark$metrics$MetricsSystem$$registry")
        registry.setAccessible(true)
        apply(registry.get(system).asInstanceOf[MetricRegistry])
    }
}
