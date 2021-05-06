package ru.gkis.soc.siem.archiver.model

sealed trait Partitions {
    def title: String
}

object Partitions {

    case object Org extends Partitions {
        def title: String = "sys_org"
    }

    case object Day extends Partitions {
        def title: String = "sys_day"
    }

    case object Month extends Partitions {
        def title: String = "sys_month"
    }

    case object Year extends Partitions {
        def title: String = "sys_year"
    }
}
