package ru.gkis.soc.siem.filter.dsl

object Transformations
    extends Serializable
        with EventReader
        with Runner
        with Transformer
        with Serializer
        with Sender
        with UnmodifiedSender
