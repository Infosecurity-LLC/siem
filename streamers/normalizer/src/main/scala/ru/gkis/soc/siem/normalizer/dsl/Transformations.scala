package ru.gkis.soc.siem.normalizer.dsl

object Transformations extends Serializable
                        with Receiver
                        with MessageParser
                        with LogParser
                        with EventValidator
                        with EventMapper
                        with Splitter
                        with Sender
                        with StatisticsCollector
                        with TimeShifter
