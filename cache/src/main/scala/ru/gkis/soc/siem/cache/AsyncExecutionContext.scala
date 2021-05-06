package ru.gkis.soc.siem.cache

import java.util.concurrent.{Executors, ThreadFactory}

import scala.concurrent.{ExecutionContext, Future, blocking}

class AsyncExecutionContext(maximumPoolSize: Int) {

    private val ec = ExecutionContext.fromExecutor(Executors.newFixedThreadPool(maximumPoolSize,
        new ThreadFactory {

            private var num = 0

            override def newThread(r: Runnable): Thread = {
                val result = new Thread(r, s"sql-async-executor-$num")
                num = num + 1
                result
            }

        }))

    def executeAsync[T](func: () => T): Future[T] = Future {
        blocking {
            func()
        }
    }(ec)

}
