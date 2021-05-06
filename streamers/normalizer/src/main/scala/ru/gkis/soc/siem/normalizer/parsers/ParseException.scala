package ru.gkis.soc.siem.normalizer.parsers

class ParseException(val root: Throwable, val src: String) extends RuntimeException(null, null, true, false)
