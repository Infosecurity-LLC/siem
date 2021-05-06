package ru.gkis.soc.siem.io.elastic

import java.util.regex.Pattern

import org.elasticsearch.hadoop.cfg.Settings
import org.elasticsearch.hadoop.serialization.SettingsAware
import org.elasticsearch.hadoop.serialization.field.{ConstantFieldExtractor, FieldExtractor}

class SocEventExtractor extends FieldExtractor with SettingsAware {

    private var fldName: String = ""

    /**
     * Pattern for replacement all invalid Elastic characters from index on underscore
     * such as - [ , ", *, \, <, |, ,, >, /, ?]
     **/
    private val pattern = Pattern.compile("""\s|"|\*|\\|<|\||,|>|\?|/""")

    override def field(target: Any): AnyRef = {
        val obj = target.asInstanceOf[UntypedMap]
        val split = fldName.split("\\.")
        val result = split.dropRight(1).foldRight(stringValueLens(split.last))((f, l) => objectLens(f) compose l) get obj
        pattern.matcher(result.toLowerCase).replaceAll("_")
    }

    override def setSettings(settings: Settings): Unit =
        fldName = settings.getProperty(ConstantFieldExtractor.PROPERTY)

}
