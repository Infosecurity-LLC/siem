package ru.gkis.soc.siem.model

case class Period(from: Short, to: Short) {

    def isBetween(time: Short): Boolean = from <= time && to >= time
}
