package ru.gkis.soc.siem.normalizer

object FinalStates {

    sealed trait State

    case object NORMALIZED extends State
    case object RAW extends State
    case object CHAIN extends State
    case object INVALID extends State
    case object ERROR extends State

    case object IDENTITY extends State

}
