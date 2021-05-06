package ru.gkis.soc.siem.spark

import org.apache.spark.{SparkConf, SparkContext}
import org.scalatest._

/** Shares a local `SparkContext` between all tests in a suite and closes it at the end */
trait SharedSparkContext extends BeforeAndAfterAll with BeforeAndAfterEach { self: Suite =>

    @transient private var _sc: SparkContext = _

    def sc: SparkContext = _sc

    var conf = new SparkConf(false)

    /**
     * Initialize the [[SparkContext]].  Generally, this is just called from beforeAll; however, in
     * test using styles other than FunSuite, there is often code that relies on the session between
     * test group constructs and the actual tests, which may need this session.  It is purely a
     * semantic difference, but semantically, it makes more sense to call 'initializeContext' between
     * a 'describe' and an 'it' call than it does to call 'beforeAll'.
     */
    protected def initializeContext(): Unit = {
        if (null == _sc) {
            _sc = new SparkContext(
                "local[4]", "test", conf.set("spark.hadoop.fs.file.impl", classOf[DebugFilesystem].getName))
        }
    }

    override def beforeAll(): Unit = {
        super.beforeAll()
        initializeContext()
    }

    override def afterAll(): Unit = {
        try {
            LocalSparkContext.stop(_sc)
            _sc = null
        } finally {
            super.afterAll()
        }
    }

    protected override def beforeEach(): Unit = {
        super.beforeEach()
        DebugFilesystem.clearOpenStreams()
    }

    protected override def afterEach(): Unit = {
        super.afterEach()
        DebugFilesystem.assertNoOpenStreams()
    }
}
