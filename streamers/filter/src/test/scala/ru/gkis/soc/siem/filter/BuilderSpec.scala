package ru.gkis.soc.siem.filter

import java.util
import org.junit.runner.RunWith
import org.python.util.PythonInterpreter
import org.scalatest.{FlatSpec, Matchers}
import org.scalatestplus.junit.JUnitRunner
import ru.gkis.soc.siem.model.PyScript


@RunWith(classOf[JUnitRunner])
class BuilderSpec extends FlatSpec with Matchers {

    private val pyScripts = List(PyScript(1,
        """event['four'] = 4
          |print 'generatedFunction1 ' + event.toString()
          |return (event, True)
          |""".stripMargin,
        "generatedFunction1"),
        PyScript(2,
            """event['two'] = 6
              |print 'generatedFunction2 ' + event.toString()
              |return (event, True)
              |""".stripMargin,
            "generatedFunction2"
        ))
    "Builder" should "create valid python script" in {
        Builder.build(pyScripts).get should be(
            """
              |import sys
              |
              |event = None
              |
              |def lens(path):
              |    nodes = path.split('.')
              |    # get (no arg)/set (value)/apply (andThen)
              |    def apply(dct, **kwargs):
              |        if 'value' in kwargs:
              |            return setval(dct, kwargs['value'])
              |        elif 'andThen' in kwargs:
              |            tmp = getval(dct)
              |            # this code relies on 'andThen' parameter contains labda
              |            if tmp is not None:
              |                return kwargs['andThen'](tmp)
              |            else:
              |                return tmp
              |        else:
              |            return getval(dct)
              |    # getter
              |    def getval(dct):
              |        res = None
              |        for node in nodes:
              |            res = dct.get(node)
              |            if res is None:
              |                break
              |            else:
              |                dct = res
              |        return res
              |    # setter
              |    def setval(dct, value):
              |        res = dct
              |        for node in nodes[:-1]:
              |            if node not in dct:
              |                dct[node] = {}
              |            dct = dct[node]
              |        dct[nodes[-1]] = value
              |        return res
              |    return apply
              |
              |def generatedFunction1():
              |    event['four'] = 4
              |    print 'generatedFunction1 ' + event.toString()
              |    return (event, True)
              |
              |def generatedFunction2():
              |    event['two'] = 6
              |    print 'generatedFunction2 ' + event.toString()
              |    return (event, True)
              |
              |def run():
              |    res = generatedFunction1()
              |    if res[1] == True:
              |        res = generatedFunction2()
              |    return res
              |""".stripMargin)
    }

    "Python script" should "return correct json" in {
        val script = Builder.build(pyScripts).fold("")(identity)
        val interpreter = new PythonInterpreter
        val jmap = new util.HashMap[String, Int]()
        jmap.put("one", 1)
        jmap.put("two", 2)
        jmap.put("three", 3)
        interpreter.exec(script)
        interpreter.set("event", jmap)
        val res = interpreter.eval("run()").__tojava__(classOf[util.List[Any]]).asInstanceOf[util.List[Any]]
        res.get(0) should be(jmap)
    }


}
