package ru.gkis.soc.siem.normalizer.validators

import ru.gkis.soc.siem.normalizer.ParsedEvent

class CiscoAsaValidator extends AbstractValidator[ParsedEvent] {

    import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._

    private val allowedDatapayloadMsgIds = Set(
        "113004",
        "113012",
        "113015",
        "605005",
        "611101",
        "111008",
        "111010",
        "106023",
        "710003",
        "104001",
        "104002",
        "105005",
        "105008",
        "105009",
        "106001",
        "106006",
        "106007",
        "106011",
        "106014"
    )

    "datapayloadMsgId" should s"be one of $allowedDatapayloadMsgIds" in { evt =>
        evt.event.extractOpt("datapayloadMsgId").fold(false)(allowedDatapayloadMsgIds.contains)
    }
}

object CiscoAsaValidator {
    val name: String = "asa00401"
    val version: Int = 1
}