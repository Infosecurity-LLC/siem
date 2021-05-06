package ru.gkis.soc.siem.model

case class TransformationPreference(devType: String, parser: Preference, validator: Preference, mapper: Preference)
