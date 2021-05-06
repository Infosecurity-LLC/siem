package ru.gkis.soc.siem.router.dsl

import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.spark.rdd.RDD
import org.json4s.JValue
import org.json4s.JsonAST.JString
import org.json4s.jackson.JsonMethods
import ru.gkis.soc.siem.router.dsl.model.ParsedMessage

import scala.util.{Failure, Success, Try}

trait Receiver {

    implicit class KafkaReceiver(rdd: RDD[ConsumerRecord[String, String]]) {

        def receive: RDD[ParsedMessage] = {
            rdd.flatMap { record =>
                Try {
                    val raw: String = record.value
                    val json: JValue = JsonMethods.parse(raw)

                    val JString(devType) = json \ "DevType"
                    val JString(organization) = json \ "Organization"
                    (devType, organization)
                } match {
                    case Success((devType, organization)) =>
                        Some(ParsedMessage(Option(record.key), organization, devType, record.value))
                    case Failure(_) =>
                        None
                }
            }
        }

    }

}
