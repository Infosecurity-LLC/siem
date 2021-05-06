package ru.gkis.soc.siem.reassembler.parsers

case class ParserError(message: String, stackTrace: String)

case class ParsedMessage(EventReceivedTime: String,
                         chain: String,
                         MessageSourceAddress: String,
                         EventTime: String,
                         Hostname: String,
                         SourceName: String,
                         DevCat: String,
                         DevSubCat: String,
                         DevType: String,
                         Organization: String,
                         OrgID: Int,
                         raw: String
                        )