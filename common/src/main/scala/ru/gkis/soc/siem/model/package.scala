package ru.gkis.soc.siem

package object model {

    type TransformationPreferences = Map[String, Map[String, TransformationPreference]]
    type ParsedLog = Map[String, AnyRef]
    type DevTypeToVendorMapping = Map[String, DeviceVendor]

}
