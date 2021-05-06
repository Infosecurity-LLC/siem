package ru.gkis.soc.siem.io.hbase

import java.time.Instant

import org.apache.hadoop.hbase.TableName
import org.apache.hadoop.hbase.client.{BufferedMutatorParams, Connection, Put}

class HBaseMutator(namespace: String, tableName: String, columnFamilyName: String, con: Connection) {

    private val columnFamily = columnFamilyName.getBytes
    private val params = new BufferedMutatorParams(TableName.valueOf(namespace, tableName))
    private val mut = con.getBufferedMutator(params)

    def put(key: String, columns: HBaseColumn*): Unit = {
        val put = new Put(key.getBytes)
        columns.foreach(col => put.addColumn(columnFamily, col._1, Instant.now().getEpochSecond * 1000, col._2))
        mut.mutate(put)
    }

    def close: Unit = {
        mut.flush()
        mut.close()
    }
}
