package ru.gkis.soc.siem.normalizer.mappers.helpers

import ru.gkis.soc.siem.model.Counterpart

trait Coalesce[T] {
    def ~>(obj: => T): T
}

object Coalesce {

    import scala.language.implicitConversions

    def apply[A](implicit coalesce: Coalesce[A]): Coalesce[A] = coalesce

    object ops {
        def ~>[A: Coalesce](a: => A): A = Coalesce[A] ~> a
        implicit class MapOps[A: Coalesce](a: A) {
            def ~>(): A = Coalesce[A] ~> a
        }
    }

    implicit def canCoalesceInt(prev: Option[Int]): Coalesce[Option[Int]] = {
        new Coalesce[Option[Int]] {
            override def ~>(next: => Option[Int]): Option[Int] = prev.orElse(next)
        }
    }

    implicit def canCoalesceString(prev: Option[String]): Coalesce[Option[String]] = {
        new Coalesce[Option[String]] {
            override def ~>(next: => Option[String]): Option[String] = prev.orElse(next)
        }
    }

    implicit def canCoalesceLong(prev: Option[Long]): Coalesce[Option[Long]] = {
        new Coalesce[Option[Long]] {
            override def ~>(next: => Option[Long]): Option[Long] = prev.orElse(next)
        }
    }

    implicit def canCoalesceObjectType(prev: Option[Counterpart]): Coalesce[Option[Counterpart]] = {
        new Coalesce[Option[Counterpart]] {
            override def ~>(next: => Option[Counterpart]): Option[Counterpart] = prev.orElse(next)
        }
    }
}
