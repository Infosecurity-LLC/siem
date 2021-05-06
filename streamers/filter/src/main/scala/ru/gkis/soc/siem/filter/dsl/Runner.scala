package ru.gkis.soc.siem.filter.dsl

import java.util

import org.apache.spark.rdd.RDD
import org.python.util.PythonInterpreter


trait Runner {

    implicit class Runner(rdd: RDD[util.HashMap[String, Any]]) extends Serializable {
        def run(script: String): RDD[util.List[Any]] = {
            rdd.mapPartitions(_.map { jmap =>
                val interpreter = new PythonInterpreter
                interpreter.exec(script)
                interpreter.set("event", jmap)
                interpreter.eval("run()").__tojava__(classOf[util.List[Any]])
                    .asInstanceOf[util.List[Any]]
            }
            )
        }
    }

}
