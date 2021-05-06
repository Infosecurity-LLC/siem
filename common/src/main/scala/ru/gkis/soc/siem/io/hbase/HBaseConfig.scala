package ru.gkis.soc.siem.io.hbase

import java.nio.charset.StandardCharsets

import com.typesafe.config.Config

trait HBaseConfig {

    protected val appConf: Config
    protected val basic: Config = appConf.getConfig("app.hbase")

    val coreSiteXmlUrl: Option[String] = if (basic.hasPath("core.xml.url")) Some(basic.getString("core.xml.url")) else None
    val hbaseSiteXmlUrl: Option[String] = if (basic.hasPath("site.xml.url")) Some(basic.getString("site.xml.url")) else None
    val hdfsSiteXmlUrl: Option[String] = if (basic.hasPath("hdfs.xml.url")) Some(basic.getString("hdfs.xml.url")) else None

    val namespace: String = basic.getString("namespace")
    val columnFamily: String = basic.getString("column.family")
    val timeColumn: Array[Byte] = basic.getString("time.column").getBytes(StandardCharsets.UTF_8)
    val eventColumn: Array[Byte] = basic.getString("event.column").getBytes(StandardCharsets.UTF_8)
    val organizationColumn: Array[Byte] = basic.getString("organization.column").getBytes(StandardCharsets.UTF_8)

    val krbPrincipal: Option[String] = if (basic.hasPath("kerberos.principal")) Some(basic.getString("kerberos.principal")) else None
    val krbKeytabLocation: Option[String] = if (basic.hasPath("kerberos.keytab")) Some(basic.getString("kerberos.keytab")) else None

}
