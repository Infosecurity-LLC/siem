package ru.gkis.soc.siem.filter.dsl

import java.util

import org.apache.spark.rdd.RDD

trait Transformer {

    implicit class Transformer(val rdd: RDD[Map[String, Any]]) extends Serializable {
        def transform(): RDD[util.HashMap[String, Any]] = rdd.mapPartitions { iter =>
            def toJMap(map: Map[String, Any]): util.HashMap[String, Any] = {
                val jmap = new util.HashMap[String, Any]()
                map.foreach {
                    case (k, v: Map[_, _]) => jmap.put(k, toJMap(v.asInstanceOf[Map[String, Any]]))
                    case (k, v) => jmap.put(k, v)
                }
                jmap
            }

            iter.map(toJMap)
        }
    }

}