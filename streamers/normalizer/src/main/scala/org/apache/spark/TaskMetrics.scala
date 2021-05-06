package org.apache.spark

import org.apache.spark.status.api.v1.StageStatus

object TaskMetrics {

    import scala.collection.JavaConversions._

    def apply(ctx: SparkContext): Seq[TaskStatus] = {
        val store = ctx.statusStore
        for {
            lastJob  <- store.jobsList(List(JobExecutionStatus.SUCCEEDED)).headOption.toSeq
            stage <- lastJob.stageIds.flatMap(store.stageData(_)).filter(_.status == StageStatus.COMPLETE)
            task <- store.taskList(stage.stageId, stage.attemptId, stage.numTasks)
            taskInfo <- task.taskMetrics.toSeq
        } yield {
            TaskStatus(task.host, task.executorId, lastJob.jobId, stage.name.split("(\\sat\\s)").last, task.index, taskInfo.executorRunTime)
        }
    }

}
