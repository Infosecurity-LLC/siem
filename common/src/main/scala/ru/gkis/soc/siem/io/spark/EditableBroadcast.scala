package ru.gkis.soc.siem.io.spark

import java.io.{ObjectInputStream, ObjectOutputStream}

import com.typesafe.scalalogging.LazyLogging
import org.apache.spark.broadcast.Broadcast
import org.apache.spark.streaming.StreamingContext

import scala.concurrent.duration._
import scala.reflect.ClassTag
import scala.reflect.runtime.universe._

class EditableBroadcast [T: ClassTag](
                                          @transient
                                          private val ssc: StreamingContext,
                                          @transient
                                          private val data: T,
                                          @transient
                                          private val period: Duration = 10 minutes
                                     )(implicit tag: TypeTag[T]) extends Serializable with LazyLogging {

    @transient
    private var bc = ssc.sparkContext.broadcast(data)

    @transient
    private var lastUpdatedAt = System.currentTimeMillis()

    def update(newValue: => T): Unit = {
        val updateTime = System.currentTimeMillis()
        if (updateTime - lastUpdatedAt >= period.toMillis) {
            logger.info(s"$bc [${tag.tpe}] time to update value")
            bc.unpersist(true)
            bc = ssc.sparkContext.broadcast(newValue)
            lastUpdatedAt = updateTime
            logger.info(s"$bc [${tag.tpe}] value updated")
        }
    }

    def value: T = bc.value

    private def writeObject(out: ObjectOutputStream): Unit = {
        out.writeObject(bc)
    }

    private def readObject(in: ObjectInputStream): Unit = {
        bc = in.readObject().asInstanceOf[Broadcast[T]]
    }
}