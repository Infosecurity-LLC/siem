package ru.gkis.soc.siem.normalizer.validators

import scala.collection.mutable.ListBuffer

abstract class AbstractValidator[T] extends Validator[T] {

    type Check = T => Boolean
    type Validation = (String, Check)
    type ValidationList = ListBuffer[Validation]

    private val specialChecks = new ListBuffer[(Check, ValidationList)]
    private val generalChecks: ValidationList = new ValidationList
    private var checkList: ValidationList = generalChecks

    private def apply(obj: T, checkList: ListBuffer[Validation]): List[String] = {
        checkList.foldLeft(List.empty[String])((res, check) => if (check._2(obj)) res else res :+ check._1)
    }

    def check(obj: T): List[String] = {
        apply(obj, specialChecks.filter(_._1(obj)).flatMap(_._2) ++= generalChecks)
    }

    protected def whether(func: Check): Check = func

    protected implicit class ValidationDSL(left: String) {
        def is(right: String): String = s"$left is $right"
        def equals(right: String): String = s"$left equals $right"
        def fits(right: String): String = s"$left fits $right"
        def should(right: String): String = s"$left should $right"
        def in(func: Check): Unit = checkList += ((left, func))
    }

    protected implicit class ConditionDSL(func: Check) {
        def check(vals: => Unit): Unit = {
            checkList = new ValidationList
            vals
            specialChecks += ((func, checkList))
            checkList = generalChecks
        }
    }

}

