package ru.gkis.soc.siem.io.elastic

import org.junit.runner.RunWith
import org.scalatest.FlatSpec
import org.scalatestplus.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class SocEventExtractorSpec extends FlatSpec {

    private val extractor = new SocEventExtractor()

    behavior of s"An ${extractor.getClass.getSimpleName}"

    it should "replace all invalid Elastic characters on underscore" in {

        val testString = Map("" -> """Kaspersky anti|*v<>i,\ru/?s""")

        assert(extractor.field(testString) == "kaspersky_anti__v__i__ru__s")

    }

}
