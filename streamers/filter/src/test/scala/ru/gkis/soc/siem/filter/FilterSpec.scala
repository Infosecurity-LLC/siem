package ru.gkis.soc.siem.filter

import org.apache.spark.rdd.RDD
import org.apache.spark.streaming.{Seconds, StreamingContext}
import org.json4s.DefaultFormats
import org.json4s.jackson.{JsonMethods, Serialization}
import org.junit.runner.RunWith
import org.scalatest.{Matchers, WordSpec}
import org.scalatestplus.junit.JUnitRunner
import ru.gkis.soc.siem.io.spark.EditableBroadcast
import ru.gkis.soc.siem.model.{PyScript, SocEvent}
import ru.gkis.soc.siem.spark.SharedSparkContext

import scala.concurrent.duration._

@RunWith(classOf[JUnitRunner])
class FilterSpec extends WordSpec with Matchers with SharedSparkContext with Serializable {

    "Streamer" should {
        "correct filter incidents" in new setup {

            import ru.gkis.soc.siem.filter.dsl.Transformations._

            val filtered: Array[Split] =
                rdd.mapPartitions(_.map(evt => {
                    implicit val formats: DefaultFormats = org.json4s.DefaultFormats
                    JsonMethods.parse(evt).extract[Map[String, Any]]
                }),
                    preservesPartitioning = true)
                    .transform()
                    .run(Builder.build(cache.value).fold("")(identity))
                    .serialize
                    .collect()

            filtered.headOption should not be empty
            val resultEvent: SocEvent = JsonMethods.parse(filtered.head.asInstanceOf[Event].value).extract[SocEvent]
            resultEvent.getSubject.getDomain should be("test")
            resultEvent.getSubject.getName should be("test")
        }
    }


    "Streamer" should {
        "filter 1 event" in new setup {

            import ru.gkis.soc.siem.filter.dsl.Transformations._

            val filtered: Array[Split] =
                rdd.mapPartitions(_.map(evt => {
                    implicit val formats: DefaultFormats = org.json4s.DefaultFormats
                    JsonMethods.parse(evt).extract[Map[String, Any]]
                }),
                    preservesPartitioning = true)
                    .transform()
                    .run(Builder.build(yetAnotherScript :: cache.value).fold("")(identity))
                    .serialize
                    .collect()

            filtered.headOption should not be empty
            val resultEvent: Statistic = filtered.head.asInstanceOf[Statistic]
            resultEvent.filteredCount should be(1)
            resultEvent.approvedCount should be(0)
        }
    }


    @transient
    trait setup {
        val name = "name"
        val domain = "domain"

        lazy val cacheSource: List[PyScript] = List(
            PyScript(1,
                """
                  |event['subject']['name'] = 'test'
                  |print 'generatedFunction1' + event.toString()
                  |return (event, True)
                  |""".stripMargin, "generatedFunction1"),
            PyScript(2,
                """
                  |event['subject']['domain'] = 'test'
                  |print 'generatedFunction2 ' + event.toString()
                  |return (event, True)
                  |""".stripMargin, "generatedFunction2")
        )

        lazy val yetAnotherScript: PyScript = PyScript(2,
            """
              |print 'generatedFunction2 ' + event.toString()
              |return (event, False)
              |""".stripMargin, "generatedFunction3")

        lazy val events: Seq[String] = Seq(defaultEvent)
        lazy val rdd: RDD[String] = sc.parallelize(events, 1)
        lazy val ctx = new StreamingContext(sc, Seconds(15))

        implicit val formats: DefaultFormats = org.json4s.DefaultFormats
        lazy val defaultEvent: String = Serialization.write(
            SocEvent().update(
                _.subject.name := name,
                _.subject.domain := domain
            ))

        lazy val cache: EditableBroadcast[List[PyScript]] = new EditableBroadcast(ctx, cacheSource, period = 60.seconds)

    }

}
