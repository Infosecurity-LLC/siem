package ru.gkis.soc.siem.filter

import ru.gkis.soc.siem.model.PyScript

object Builder extends Serializable {

    def build(pyScripts: List[PyScript]): Option[String] = if (pyScripts.nonEmpty) {
        Some(s"""
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
           |${pyScripts.map(script =>
            s"""def ${script.methodName}():
               |${script.script.lines.map(str => "    " + str).mkString(System.lineSeparator())}"""
                .stripMargin + System.lineSeparator())
           .mkString(System.lineSeparator())}
           |def run():
           |    ${
            pyScripts.tail.foldLeft("res = " + pyScripts.head.methodName + "()") { (acc, el) =>
                acc +
                    s"""
                       |    if res[1] == True:
                       |        res = ${el.methodName}()""".stripMargin
            }
        }
           |    return res
           |""".stripMargin)
    } else None
}
