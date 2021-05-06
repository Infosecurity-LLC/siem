package ru.gkis.soc.siem.enricher

import com.google.common.collect.{Range => NumericRange}

package object controls {

    val anyString  : String = "*"
    val anyRange: NumericRange[Integer] = NumericRange.singleton[Integer](0)

}
