package ru.gkis.soc.siem.normalizer.validators

class SymantecValidator extends KasperskyValidator {
    // at this moment there is no difference in validation logic
}

object SymantecValidator {
    val name: String = "symantec"
    val version: Int = 1
}