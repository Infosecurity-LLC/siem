package ru.gkis.soc.siem.normalizer

import scala.annotation.tailrec

object Tesst extends App {

    sealed trait BorderType {
        def rank: Int
    }
    case object Unknown extends BorderType {
        override def rank: Int = 0
    }
    case object Lower extends BorderType {
        override def rank: Int = -1
    }
    case object Upper extends BorderType {
        override def rank: Int = 1
    }

    trait OrderingConstants {
        protected val eq = 0
        protected val lte: Int = -1
        protected val gte: Int = 1
    }

    sealed trait Border[T] extends Ordered[Border[T]] with OrderingConstants {
        protected var bType: BorderType = Unknown
        def point: T
        def asString: String
        def samePoint(that: Border[T]): Boolean
        def isInfinity: Boolean
        def isOpen: Boolean
        def isClosed: Boolean
        def setLower(): Unit = bType = Lower
        def setUpper(): Unit = bType = Upper
        def isUpper: Boolean = bType == Upper
        def isLower: Boolean = bType == Lower
    }

    case class Open[T](point: T)(implicit ordering: T => Ordered[T]) extends Border[T] {
        override def compare(that: Border[T]): Int = {
            that match {
                case Open(thatPoint)   =>
                    val compared = point compare thatPoint
                    if (compared == eq) {
                        if (this.isUpper && that.isLower) lte
                        else if (this.isLower && that.isUpper) gte
                        else eq
                    }
                    else compared
                case Closed(thatPoint) =>
                    val compared = point compare thatPoint
                    if (compared == eq) {
                        if (this.isUpper && that.isLower) lte
                        else if (this.isUpper && that.isUpper) lte
                        else gte
                    }
                    else compared
                case thatPoint if thatPoint == PositiveInfinity => lte
                case thatPoint if thatPoint == NegativeInfinity => gte
            }
        }
        override def samePoint(that: Border[T]): Boolean = {
            if (that == PositiveInfinity || that == NegativeInfinity) false else (point compare that.point) == eq
        }
        override def isInfinity: Boolean = false
        override def isOpen: Boolean = true
        override def isClosed: Boolean = false
        override def asString: String = point.toString
    }

    case class Closed[T](point: T)(implicit ordering: T => Ordered[T]) extends Border[T] {
        override def compare(that: Border[T]): Int = {
            that match {
                case Closed(thatPoint) => point compare thatPoint
                case Open(thatPoint)   =>
                    val compared = point compare thatPoint
                    if (compared == eq) {
                        if (this.isLower && that.isUpper) gte
                        else if (this.isLower && that.isLower) gte
                        else lte
                    }
                    else compared
                case thatPoint if thatPoint == PositiveInfinity => lte
                case thatPoint if thatPoint == NegativeInfinity => gte
            }
        }
        override def samePoint(that: Border[T]): Boolean = {
            if (that == PositiveInfinity || that == NegativeInfinity) false else (point compare that.point) == eq
        }
        override def isInfinity: Boolean = false
        override def isOpen: Boolean = false
        override def isClosed: Boolean = true
        override def asString: String = point.toString
    }

    case object PositiveInfinity extends Border[Nothing] {
        def apply[T](): Border[T] = this.asInstanceOf[Border[T]]
        override def point: Nothing = throw new RuntimeException("Positive infinity is not a point")
        override def compare(that: Border[Nothing]): Int = if (that == PositiveInfinity) eq else gte
        override def samePoint(that: Border[Nothing]): Boolean = if (that == PositiveInfinity) true else false
        override def isInfinity: Boolean = true
        override def isOpen: Boolean = true
        override def isClosed: Boolean = false
        override def asString: String = "+∞"
    }

    case object NegativeInfinity extends Border[Nothing] {
        def apply[T](): Border[T] = this.asInstanceOf[Border[T]]
        override def point: Nothing = throw new RuntimeException("Negative infinity is not a point")
        override def compare(that: Border[Nothing]): Int = if (that == NegativeInfinity) eq else lte
        override def samePoint(that: Border[Nothing]): Boolean = if (that == NegativeInfinity) true else false
        override def isInfinity: Boolean = true
        override def isOpen: Boolean = true
        override def isClosed: Boolean = false
        override def asString: String = "-∞"
    }

    case class Interval[T](from: Border[T], to: Border[T])(implicit ordering: T => Ordered[T]) extends Ordered[Interval[T]] with OrderingConstants {
        if (from > to) throw new IllegalArgumentException(s"Interval start should be less or equal to end. Got from=$from and to=$to")

        from.setLower()
        to.setUpper()

        private def max(point1: Border[T], point2: Border[T]) = if (point1 >= point2) point1 else point2
        private def min(point1: Border[T], point2: Border[T]) = if (point1 <= point2) point1 else point2

        def isSinglePoint: Boolean = from == to
        def touchesLeft(that: Interval[T]): Boolean = (to, that.from) match {
            case (upper: Open[T], lower: Closed[T]) => if (upper samePoint lower) true else false
            case (upper: Closed[T], lower: Open[T]) => if (upper samePoint lower) true else false
            case _ => false
        }
        def touchesRight(that: Interval[T]): Boolean = (that.to, from) match {
            case (upper: Open[T], lower: Closed[T]) => if (upper samePoint lower) true else false
            case (upper: Closed[T], lower: Open[T]) => if (upper samePoint lower) true else false
            case _ => false
        }
        def touches(that: Interval[T]): Boolean = touchesRight(that) || touchesLeft(that)
        def contains(that: Interval[T]): Boolean = (from <= that.from) && (to >= that.to)
        def contains(point: Border[T]): Boolean = (from <= point) && (to >= point)
        def intersects(that: Interval[T]): Boolean = max(from, that.from) <= min(to, that.to)
        def append(right: Interval[T]): Interval[T] = {
            if (!this.touchesLeft(right)) throw new IllegalArgumentException("Can append touching intervals only")
            Interval(from, right.to)
        }
        def prepend(left: Interval[T]): Interval[T] = {
            if (!this.touchesRight(left)) throw new IllegalArgumentException("Can append touching intervals only")
            Interval(left.from, to)
        }
        override def compare(that: Interval[T]): Int = {
            if (from == that.from && to == that.to) eq
            else if (this.intersects(that)) throw new IllegalArgumentException("Cannot compare intersecting intervals")
            else if (from > that.to) gte
            else lte
        }
        override def toString: String = (from, to) match {
            case (from: Closed[T], to: Closed[T])   => s"[${from.asString}, ${to.asString}]"
            case (from: Border[T], to: Closed[T])   => s"(${from.asString}, ${to.asString}]"
            case (from: Closed[T], to: Border[T])   => s"[${from.asString}, ${to.asString})"
            case (from: Border[T], to: Border[T])   => s"(${from.asString}, ${to.asString})"
        }
    }

    class IntervalTrie[K, V](implicit ordering: K => Ordered[K]) extends OrderingConstants {

        private case class Node(key: Interval[K] , value: Set[V])

        private var trie = List(Node(Interval(NegativeInfinity(), PositiveInfinity()), Set.empty))

        private def complement(point: (Border[K], BorderType)): (Border[K], Border[K]) = point match {
            case (p: Open[K], Lower)   => Closed(p.point) -> p
            case (p: Open[K], Upper)   => p -> Closed(p.point)
            case (p: Closed[K], Lower) => Open(p.point) -> p
            case (p: Closed[K], Upper) => p -> Open(p.point)
            case other => (other._1, other._1)
        }

        def add(key: Interval[K], value: Set[V]): Unit = {
            trie = trie
                .flatMap {
                    case Node(curr, currValue) =>
                        // same intervals
                        if (curr == key) {
                            List(Node(curr, currValue union value))
                        }
                        // new interval is inside this interval
                        else if (curr contains key) {
                            val complementedFrom = complement(key.from, Lower)
                            val complementedTo = complement(key.to, Upper)
                            List(
                                Node(Interval(curr.from, complementedFrom._1), currValue),
                                Node(Interval(complementedFrom._2, complementedTo._1), currValue union value),
                                Node(Interval(complementedTo._2, curr.to), currValue)
                            )
                        }
                        // curr inside key
                        else if (key contains curr) {
                            List(Node(curr, currValue union value))
                        }
                        // key left side hit
                        else if (curr contains key.from) {
                            val complementedFrom = complement(key.from, Lower)
                            List(
                                Node(Interval(curr.from, complementedFrom._1), currValue),
                                Node(Interval(complementedFrom._2, curr.to), currValue union value)
                            )
                        }
                        // key right side hit
                        else if (curr contains key.to) {
                            val complementedTo = complement(key.to, Upper)
                            List(
                                Node(Interval(curr.from, complementedTo._1), currValue union value),
                                Node(Interval(complementedTo._2, curr.to), currValue)
                            )
                        }
                        // no hit
                        else {
                            List(Node(curr, currValue))
                        }
                }
                .filterNot(el => el.key.isSinglePoint && el.key.from.isOpen && el.key.to.isOpen)
        }

        def search(what: K): Option[Set[V]] = {
            search(Interval(Closed(what), Closed(what)), 0, trie.size - 1) match {
                case Some(res) =>
                    assert(res._1 == res._2)
                    if (trie(res._1).value.isEmpty) None else Some(trie(res._1).value)
                case None =>
                    None
            }

        }

        @tailrec
        private def search(what: Interval[K], from: Int, to: Int): Option[(Int, Int)] = {
            val idx = from + ((to.toDouble - from.toDouble) / 2.toDouble).toInt
            val mid = trie(idx)
            if (mid.key intersects what) {
                val begins = (from until idx).reverse.foldLeft(idx)((res, i) => if (trie(i).key intersects what) i else res)
                val ends = (idx to to).foldLeft(idx)((res, i) => if (trie(i).key intersects what) i else res)
                Some((begins, ends))
            }
            else if (idx == from || idx == to) {
                None
            }
            else {
                if (mid.key > what) search(what, from, idx)
                else search(what, idx, to)
            }
        }

        override def toString: String = trie.map(n => s"${n.key} -> {${n.value.mkString(",")}}").mkString(",")

    }

    val it = new IntervalTrie[Int, Int]
    it.add(Interval[Int](NegativeInfinity(), Closed(-10)), Set(1))
    it.add(Interval[Int](Closed(0), Open(10)), Set(2))
    it.add(Interval[Int](Closed(20), PositiveInfinity()), Set(3))
    it.add(Interval[Int](Closed(15), Closed(15)), Set(15))
    it.add(Interval[Int](Open(-5), Open(25)), Set(4))
    it.add(Interval[Int](NegativeInfinity(), Open(5)), Set(5))
    it.add(Interval[Int](Closed(15), Closed(15)), Set(16))
    it.add(Interval[Int](Open(-5), Open(7)), Set(400))
    it.add(Interval[Int](NegativeInfinity(), PositiveInfinity()), Set(0))
//    it.add(Interval[Int](Open(10), Open(15)), Set(1))
//    it.add(Interval[Int](Open(15), Open(20)), Set(2))
    System.out.println(it)

    val res = it.search(15)
    System.out.println(res)
}