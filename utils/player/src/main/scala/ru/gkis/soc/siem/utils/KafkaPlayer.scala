package ru.gkis.soc.siem.utils

import java.nio.file.Paths
import java.util.Properties

import org.apache.commons.cli.{CommandLine, DefaultParser, HelpFormatter, Options, Option => CliOption}
import org.apache.kafka.clients.producer.{KafkaProducer, ProducerRecord}
import org.apache.kafka.common.serialization.StringSerializer

import scala.io.Source
import scala.util.{Failure, Success, Try}

object KafkaPlayer extends App {

    val options = buildOptions()
    val parser = new DefaultParser

    Try(parser.parse(options, args)) match {
        case Failure(ex) =>
            System.err.println(s"Fail to parse argument, because: ${ex.getMessage}")
            printHelp()
        case Success(cmd) =>
            (cmd.maybeString('a'), cmd.maybeString('t'), cmd.maybeString('f')) match {
                case (Some(address), Some(topic), Some(file)) =>
                    Try(Paths.get(file)).toOption match {
                        case None =>
                            System.err.println(s"Can't read file with path [$file]")
                        case Some(_) =>
                            val props: Properties = kafkaConfig(cmd, address)

                            val producer = new KafkaProducer(props, new StringSerializer(), new StringSerializer())
                            //                            val source = Source
                            //                                .fromInputStream(this.getClass.getResourceAsStream(file))
                            //                                .getLines()
                            val time = System.currentTimeMillis().toString
                            val id = time.takeRight(8)
                            val timeStamp = s"${time.take(10)}.${time.takeRight(3)}"

                            //                            lines.foreach { line =>
                            //                                producer.send(
                            //                                    new ProducerRecord[String, String](topic, null, line)
                            //                                )
                            //                            }
                            val source = Source
                                .fromInputStream(this.getClass.getResourceAsStream(file))
                                .getLines()

                            while (source.hasNext) {
                                val line: String = source.next()
                                val result: String = line.replace("1605096181.374:18144559", s"$timeStamp:$id")
                                producer.send(
                                    new ProducerRecord[String, String](topic, null, result)
                                )
                            }

                            producer.flush()
                            producer.close()

                            System.out.println(s"Operation completed")
                            System.out.println(
                                s"Sent $file[a lot items] data into Kafka topic $topic[$address]")
                    }
                case _ =>
                    printHelp()
            }
    }

    private[this] def kafkaConfig(cmd: CommandLine, address: String) = {
        val props = new Properties()
        props.put("bootstrap.servers", address)
        props.put("acks", "all")
        props.put("retries", "0")
        props.put("batch.size", "16384")
        props.put("linger.ms", "1")
        props.put("buffer.memory", "33554432")
        props.put("key.serializer",
            "org.apache.kafka.common.serialization.StringSerializer")
        props.put("value.serializer",
            "org.apache.kafka.common.serialization.StringSerializer")

        (cmd.maybeString('p'), cmd.maybeString('k')) match {
            case (Some(principal), Some(keyTab)) =>
                props.put("useKeyTab", "true")
                props.put("com.sun.security.auth.module.Krb5LoginModule", "required")
                props.put("storeKey", "true")
                props.put("useTicketCache", "false")
                props.put("principal", principal)
                props.put("keyTab", keyTab)
            case _ =>
        }
        props
    }

    private[this] def printHelp(): Unit = {
        System.err.println("Error parsing command-line arguments!")
        System.out.println("Please, follow the instructions below:")
        val formatter: HelpFormatter = new HelpFormatter
        formatter.printHelp("Log messages to sequence diagrams converter", options)
    }

    private[this] def buildOptions() = {
        new Options()
            .addOption(
                CliOption
                    .builder("a")
                    .longOpt("address")
                    .hasArg(true)
                    .desc("Kafka address [REQUIRED]")
                    .required(false)
                    .build)
            .addOption(
                CliOption
                    .builder("t")
                    .longOpt("topic")
                    .hasArg(true)
                    .desc("Kafka topic [REQUIRED]")
                    .required(false)
                    .build)
            .addOption(
                CliOption
                    .builder("f")
                    .longOpt("file")
                    .hasArg(true)
                    .desc("File with events [REQUIRED]")
                    .required
                    .build)
            .addOption(
                CliOption
                    .builder("p")
                    .longOpt("principal")
                    .hasArg(true)
                    .desc("Kerberos principal [REQUIRED - if you want to use kerberos]")
                    .build)
            .addOption(
                CliOption
                    .builder("k")
                    .longOpt("keytab")
                    .hasArg(true)
                    .desc("Kerberos keyTab [REQUIRED - if you want to use kerberos]")
                    .build)
    }

    implicit class RichCommandLine(cmd: CommandLine) {
        def maybeString(char: Char): Option[String] = {
            Option(cmd.getOptionValue(char))
        }
    }

}
