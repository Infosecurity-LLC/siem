package org.apache.spark.metrics.source

import java.util.concurrent.atomic.AtomicLong
import java.util.regex.Pattern

import com.codahale.metrics.{Gauge, Histogram}

trait Metrics extends Source {

    private val replaceDotsAndSpaces = Pattern.compile("""\.| """)
    private val replaceNonAlphanumeric = Pattern.compile("""[^a-zA-Z\d-_]""")

    protected def replaceInvalidCharacters(source: String): String = {
        replaceNonAlphanumeric
            .matcher(replaceDotsAndSpaces.matcher(source).replaceAll("_"))
            .replaceAll("")
    }

    protected def set(metricKey: String, value: Long): Unit = {
        val gauges = metricRegistry.getMetrics

        if (gauges.containsKey(metricKey)) {
            val gauge = gauges.get(metricKey).asInstanceOf[EditableCounterGauge]
            gauge.set(value)
        } else {
            val gauge = new EditableCounterGauge
            gauge.set(value)
            metricRegistry.register(metricKey, gauge)
        }
    }

    protected def add(metricKey: String, value: Long): Unit = {
        val gauges = metricRegistry.getMetrics

        if (gauges.containsKey(metricKey)) {
            val gauge = gauges.get(metricKey).asInstanceOf[EditableCounterGauge]
            gauge.add(value)
        } else {
            val gauge = new EditableCounterGauge
            gauge.add(value)
            metricRegistry.register(metricKey, gauge)
        }
    }

    protected def hist(metricKey: String, value: Long): Unit = {
        val histograms = metricRegistry.getMetrics

        if (histograms.containsKey(metricKey)) {
            val hist = histograms.get(metricKey).asInstanceOf[Histogram]
            hist.update(value)
        } else {
            val hist = metricRegistry.histogram(metricKey)
            hist.update(value)
        }
    }


    class EditableCounterGauge extends Gauge[Long] {

        private val value = new AtomicLong(0L)

        override def getValue: Long = value.get()

        def add(newValue: Long): Long = value.addAndGet(newValue)

        def set(newValue: Long): Unit = value.set(newValue)
    }

}
