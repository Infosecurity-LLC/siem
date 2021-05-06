package org.apache.spark

case class TaskStatus(host: String, executorId: String, jobId: Int, stageName: String, taskIndex: Int, execTime: Long)
