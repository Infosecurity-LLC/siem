package ru.gkis.soc.siem.archiver

import java.net.URI
import java.nio.charset.StandardCharsets
import java.time._
import java.time.temporal.{ChronoUnit, TemporalUnit}

import com.typesafe.scalalogging.LazyLogging
import org.apache.hadoop.fs.{FileSystem, Path}
import org.apache.hadoop.hbase.HBaseConfiguration
import org.apache.hadoop.hbase.client.Result
import org.apache.hadoop.hbase.io.ImmutableBytesWritable
import org.apache.hadoop.hbase.mapreduce.{TableInputFormat, TableInputFormatBase, TableOutputFormat}
import org.apache.hadoop.mapreduce.Job
import org.apache.spark.SparkConf
import org.apache.spark.rdd.RDD
import org.apache.spark.sql.catalyst.TableIdentifier
import org.apache.spark.sql.types.{DataTypes, IntegerType, StructField}
import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.execution.command.AlterTableAddPartitionCommand
import ru.gkis.soc.siem.archiver.model.PartitionsColumns
import ru.gkis.soc.siem.commons.BaseConfig
import ru.gkis.soc.siem.io.hive.HiveConfig
import ru.gkis.soc.siem.io.hbase._

import scala.util.{Failure, Success, Try}

object Main extends LazyLogging {

    def main(args: Array[String]): Unit = {


        import ru.gkis.soc.siem.archiver.dsl.Transformations._
        import ru.gkis.soc.siem.archiver.model.Partitions._
        import scala.collection.JavaConversions._
        import org.apache.spark.sql.functions.{col, date_format, from_unixtime, to_utc_timestamp}

        val rawDate = if (args.length == 1) args(0)
                      else throw new IllegalArgumentException("Argument execution_date in ISO8601 format is required!")

        // Airflow provides us with T-1 execution date. Just make sure it is in UTC zone
        val date = ZonedDateTime.parse(rawDate).withZoneSameInstant(ZoneOffset.UTC)
        // calculate start and end of day
        val from = date.toInstant.truncatedTo(ChronoUnit.DAYS)
        val to = from.plusSeconds(86399).plusMillis(999) // 86400 seconds minus one and 999 millis

        val conf = new BaseConfig with HBaseInputConfig with HiveConfig with ArchiverConf
        val sparkConf = new SparkConf().setAll(conf.sparkProperties + conf.hiveUri)
        val hadoopConf = HBaseConfiguration.create()
        conf.hbaseSiteXmlUrl.map(new Path(_)).foreach(hadoopConf.addResource)
        conf.coreSiteXmlUrl.map(new Path(_)).foreach(hadoopConf.addResource)
        conf.hdfsSiteXmlUrl.map(new Path(_)).foreach(hadoopConf.addResource)
        hadoopConf.set(TableInputFormat.INPUT_TABLE, conf.hbaseTable)
        hadoopConf.set(TableOutputFormat.OUTPUT_TABLE, conf.hbaseTable)
        hadoopConf.set(TableInputFormat.SCAN_TIMERANGE_START, from.toEpochMilli.toString)
        hadoopConf.set(TableInputFormat.SCAN_TIMERANGE_END, to.toEpochMilli.toString)
        hadoopConf.set(TableInputFormatBase.MAPREDUCE_INPUT_AUTOBALANCE, "true")
        hadoopConf.set(TableInputFormat.SCAN_BATCHSIZE, "10000")
        val job = Job.getInstance(hadoopConf, this.getClass.getName)
        job.setOutputFormatClass(classOf[TableOutputFormat[_]])

        logger.info(s"Running archivation process for table '${conf.hbaseTable}' with date $rawDate [from=$from to=$to]")

        val session = SparkSession
                            .builder()
                            .config(sparkConf)
                            .enableHiveSupport()
                            .getOrCreate()

        // read hbase table files
        val rdd: RDD[(ImmutableBytesWritable, Result)] = session.sparkContext.newAPIHadoopRDD(
            hadoopConf,
            classOf[org.apache.hadoop.hbase.mapreduce.TableInputFormat],
            classOf[org.apache.hadoop.hbase.io.ImmutableBytesWritable],
            classOf[org.apache.hadoop.hbase.client.Result]
        )

        val hconf = session.sparkContext.broadcast(conf.asInstanceOf[HBaseInputConfig])

        val fields: List[StructField] = ProtoSchema(conf.eventType.scalaDescriptor)
                                            .map {
                                                case (name, field) => StructField(name, field.sqlType, nullable = true)
                                            }
                                            .toList

        // now we have fields - can convert data to rows and create Dataframe
        val orgColumnName = conf.partitionColumnOrg
        val dateColumnName = conf.partitionColumnDate
        val df = session
            .createDataFrame(rdd.toDataframeRows(from.toEpochMilli, to.toEpochMilli, hconf), DataTypes.createStructType(fields))
            .withColumn(Org.title, col(orgColumnName))
            .withColumn(Year.title, date_format(to_utc_timestamp(from_unixtime(col(dateColumnName)), ZoneId.systemDefault().getId), "yyyy").cast(IntegerType))
            .withColumn(Month.title, date_format(to_utc_timestamp(from_unixtime(col(dateColumnName)), ZoneId.systemDefault().getId), "MM").cast(IntegerType))
            .withColumn(Day.title, date_format(to_utc_timestamp(from_unixtime(col(dateColumnName)), ZoneId.systemDefault().getId), "dd").cast(IntegerType))
            .repartition(col(Org.title), col(Year.title), col(Month.title), col(Day.title))


        val res = Try(  // write dataframe to orc files
            df
            .write
            .mode(conf.saveMode)
            .partitionBy(Org.title, Year.title, Month.title, Day.title)
            .orc(conf.outputDir)
        )

        // check write result and add new partitions to Hive table
        res match {
            case Success(_) =>  // on success add hive partition to a table
                val fs = FileSystem.get(session.sparkContext.hadoopConfiguration)
                val newPartitions =
                    fs
                        .listStatus(new Path(new URI(conf.outputDir).getPath))
                        .filter(_.isDirectory)
                        // skip  characters (`sys_org=` length)
                        .map(p => p.getPath.getName.substring(8) -> p.getPath.toString)
                        .map {
                            case (org, base) =>
                                PartitionsColumns(org, date.getYear, date.getMonth.getValue, date.getDayOfMonth) -> base
                        }
                        .map {  // guess new partition location
                            case (partition, base) =>
                                partition -> new Path(s"$base/sys_year=${partition.year}/" +
                                                                 s"sys_month=${partition.month}/" +
                                                                 s"sys_day=${partition.day}")
                        }
                        .filter {  // check new partition location really exists
                            case (_, location) => fs.exists(location)
                        }
                        .map {  // convert to partition info for table alter command
                            case (partition, _) =>
                                Map(Org.title   -> partition.org,
                                    Year.title  -> partition.year.toString,
                                    Month.title -> partition.month.toString,
                                    Day.title   -> partition.day.toString)
                        }

                if (newPartitions.nonEmpty) {
                    logger.info(s"Adding new partitions to ${conf.hbaseTable} table: \n  ${newPartitions.mkString("\n  ")}")
                    val alter = AlterTableAddPartitionCommand(
                        TableIdentifier(conf.hiveTable),
                        newPartitions.map(_ -> None),
                        ifNotExists = true
                    )
                    alter.run(session)
                }
                else {
                    logger.warn("No new partitions detected! Skip Hive alter operation")
                }

            case Failure(ex) =>  // on failure write log message
                throw new RuntimeException("Could not save data to Hive", ex)
        }

    }
}
