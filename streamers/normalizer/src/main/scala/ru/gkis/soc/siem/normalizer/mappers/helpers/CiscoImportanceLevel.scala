package ru.gkis.soc.siem.normalizer.mappers.helpers

import ru.gkis.soc.siem.model.ImportanceLevel

object CiscoImportanceLevel {
    def apply(value: String): ImportanceLevel = {
        value match {
            case "1" | "5" | "6" | "7" =>
                ImportanceLevel.INFO
            case "3" =>
                ImportanceLevel.LOW
            case "4" =>
                ImportanceLevel.MEDIUM
            case "2" =>
                ImportanceLevel.HIGH
        }
    }
}
