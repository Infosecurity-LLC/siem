package ru.gkis.soc.siem.utils

import ch.qos.logback.classic
import ch.qos.logback.classic.Level
import org.apache.commons.cli.{CommandLine, DefaultParser, HelpFormatter, Options, ParseException, Option => CliOption}
import org.apache.kafka.clients.consumer.KafkaConsumer
import org.apache.kafka.common.TopicPartition
import org.apache.kafka.common.serialization.StringDeserializer
import org.slf4j.{Logger, LoggerFactory}

import scala.util.{Failure, Success, Try}

object KafkaReset extends App {

    import scala.collection.JavaConversions._


    val options = buildOptions()
    val parser = new DefaultParser

    Try(parser.parse(options, args)) match {
        case Failure(ex) =>
            System.err.println(s"Fail to parse argument, because: ${ex.getMessage}")
            printHelp()
        case Success(cmd) =>
            (cmd.maybeString('a'), cmd.maybeString('g'), cmd.maybeString('t')) match {
                case (Some(address), Some(group), maybeTopic) =>
                    // turn off kafka logging
                    val root = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME).asInstanceOf[classic.Logger]
                    root.setLevel(Level.ERROR)

                    val props: Map[String, AnyRef] = kafkaConfiguration(cmd, address, group)
                    System.out.println(s"Starting reset process for consumer group `$group` ${maybeTopic.map(t => s"topic $t").getOrElse("")}")

                    val consumer = new KafkaConsumer[String, String](props)
                    val topics = consumer.listTopics()

                    topics
                        .collect { case (topic, partitions) if "__consumer_offsets" != topic && maybeTopic.forall(_ == topic) =>
                            (topic, partitions.map(pi => new TopicPartition(topic, pi.partition())))
                        }
                        .map { case (topic, partitions) =>
                            System.out.println(createHeader(topic))

                            val needReset = partitions
                                .map(tp => (tp.partition(), Option(consumer.committed(tp))))
                                .map {
                                    case (part, Some(committed)) =>
                                        System.out.println(s"Partition #$part commited offset is ${committed.offset()}... ")
                                        true
                                    case (part, None) =>
                                        System.out.println(s"Partition #$part was never read by consumer group `$group`")
                                        false
                                }
                                .foldLeft(false)((res, n) => res || n)

                            if (needReset) {
                                consumer.assign(partitions)
                                consumer.seekToEnd(partitions)
                                consumer.poll(0)
                                consumer.commitSync()
                                System.out.println("Reset")
                            }
                        }
                case _ =>
                    printHelp()
            }
    }

    private[this] def kafkaConfiguration(cmd: CommandLine, address: String, group: String): Map[String, AnyRef] = {
        val common = Map[String, AnyRef](
            "bootstrap.servers" -> address,
            "key.deserializer" -> classOf[StringDeserializer],
            "value.deserializer" -> classOf[StringDeserializer],
            "group.id" -> group,
            "auto.offset.reset" -> "none",
            "enable.auto.commit" -> "false"
        )

        (cmd.maybeString('p'), cmd.maybeString('k')) match {
            case (Some(principal), Some(keyTab)) =>
                common ++ Map(
                    "useKeyTab" -> "true",
                    "com.sun.security.auth.module.Krb5LoginModule" -> "required",
                    "storeKey" -> "true",
                    "useTicketCache" -> "false",
                    "principal" -> principal,
                    "keyTab" -> keyTab
                )
            case _ =>
                common
        }
    }

    implicit class RichCommandLine(cmd: CommandLine) {
        def maybeString(char: Char): Option[String] = {
            Option(cmd.getOptionValue(char))
        }
    }

    private[this] def createHeader(topic: String): String = {
        val res = new StringBuilder()
        res.append(s"Reset offsets for topic `$topic` to its end ")
        res.length.to(100).foreach(_ => res.append('='))
        res.toString()
    }

    private[this] def buildOptions(): Options = {
        new Options()
            .addOption(
                CliOption
                    .builder("a")
                    .longOpt("address")
                    .hasArg(true)
                    .desc("Kafka address [REQUIRED]")
                    .required(false)
                    .build
            )
            .addOption(
                CliOption
                    .builder("g")
                    .longOpt("group")
                    .hasArg(true)
                    .desc("Kafka consumer groupFile [REQUIRED]")
                    .required
                    .build
            )
            .addOption(
                CliOption
                    .builder("t")
                    .longOpt("topic")
                    .hasArg(true)
                    .desc("Kafka topic")
                    .build
            )
            .addOption(
                CliOption
                    .builder("p")
                    .longOpt("principal")
                    .hasArg(true)
                    .desc("Kerberos principal [REQUIRED - if you want to use kerberos]")
                    .build
            )
            .addOption(
                CliOption
                    .builder("k")
                    .longOpt("keytab")
                    .hasArg(true)
                    .desc("Kerberos keyTab [REQUIRED - if you want to use kerberos]")
                    .build
            )
    }

    private[this] def printHelp(): Unit = {
        System.err.println("Error parsing command-line arguments!")
        System.out.println("Please, follow the instructions below:")
        val formatter: HelpFormatter = new HelpFormatter
        formatter.printHelp("Log messages to sequence diagrams converter", options)
    }
}
