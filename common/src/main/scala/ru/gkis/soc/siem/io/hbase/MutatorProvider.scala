package ru.gkis.soc.siem.io.hbase

import java.security.PrivilegedExceptionAction
import java.util.concurrent.{Executors, ThreadFactory}

import org.apache.hadoop.fs.Path
import org.apache.hadoop.hbase.HBaseConfiguration
import org.apache.hadoop.hbase.client.{Connection, ConnectionFactory}
import org.apache.hadoop.security.UserGroupInformation
import ru.gkis.soc.siem.commons.Provider
import ru.gkis.soc.siem.model.{ChainEvent, RawEvent, SocEvent}
import scalapb.GeneratedMessageCompanion

class MutatorProvider() extends Provider[HBaseOutputConfig, Connection] with Serializable {

    def createMutator(companion: GeneratedMessageCompanion[_], hbaseConf: HBaseOutputConfig): HBaseMutator = {
        val connection = get(hbaseConf, spawner)
        createMutatorInternal(hbaseConf, connection)(companion)
    }

    private def createMutatorInternal(hbaseConf: HBaseOutputConfig, connection: Connection): PartialFunction[AnyRef, HBaseMutator] = {
        case SocEvent => new HBaseMutator(hbaseConf.namespace, hbaseConf.socEventMapping.table, hbaseConf.columnFamily, connection)
        case RawEvent => new HBaseMutator(hbaseConf.namespace, hbaseConf.rawEventMapping.table, hbaseConf.columnFamily, connection)
        case ChainEvent => new HBaseMutator(hbaseConf.namespace, hbaseConf.chainEventMapping.table, hbaseConf.columnFamily, connection)
    }

    private def spawner: HBaseOutputConfig => Connection = hbaseConf => {
        val hadoopConf = HBaseConfiguration.create()
        hbaseConf.hbaseSiteXmlUrl.map(new Path(_)).foreach(hadoopConf.addResource)
        hbaseConf.coreSiteXmlUrl.map(new Path(_)).foreach(hadoopConf.addResource)
        hbaseConf.hdfsSiteXmlUrl.map(new Path(_)).foreach(hadoopConf.addResource)
        val ec = Executors.newFixedThreadPool(hbaseConf.hbaseConnectionParallelism,
            new ThreadFactory {

                private var num = 0

                override def newThread(r: Runnable): Thread = {
                    val result = new Thread(r, s"hbase-async-executor-$num")
                    num = num + 1
                    result
                }

            })
        Option((hbaseConf.krbPrincipal, hbaseConf.krbKeytabLocation))
            .map {
                case (Some(principal), Some(keytab)) =>
                    val ugi = UserGroupInformation.loginUserFromKeytabAndReturnUGI(principal, keytab)
                    UserGroupInformation.setLoginUser(ugi)
                    ugi.doAs(new PrivilegedExceptionAction[Connection]() {
                        override def run(): Connection = ConnectionFactory.createConnection(hadoopConf, ec)
                    })
                case _ => ConnectionFactory.createConnection(hadoopConf, ec)
            }
            .get
    }

}
