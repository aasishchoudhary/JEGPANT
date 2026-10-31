package com.jegpant.app.net

import org.json.JSONObject

/**
 * Canonical JSON compatible with Python json.dumps(sort_keys=True,
 * separators=(",", ":"), ensure_ascii=False) for the JEGPANT signing schemas.
 */
object CanonicalJson {
    fun encode(values: Map<String, Any?>): ByteArray =
        encodeObject(values).toByteArray(Charsets.UTF_8)

    private fun encodeObject(values: Map<String, Any?>): String =
        values.toSortedMap().entries.joinToString(
            prefix = "{",
            postfix = "}",
            separator = ","
        ) { (key, value) ->
            "${JSONObject.quote(key)}:${encodeValue(value)}"
        }

    private fun encodeValue(value: Any?): String = when (value) {
        null -> "null"
        is String -> JSONObject.quote(value)
        is Boolean -> if (value) "true" else "false"
        is Byte, is Short, is Int, is Long -> value.toString()
        is Float -> {
            require(value.isFinite()) { "Non-finite JSON number" }
            value.toString()
        }
        is Double -> {
            require(value.isFinite()) { "Non-finite JSON number" }
            value.toString()
        }
        is List<*> -> value.joinToString(
            prefix = "[",
            postfix = "]",
            separator = ","
        ) { encodeValue(it) }
        is Map<*, *> -> {
            val stringMap = value.entries.associate { (key, item) ->
                require(key is String) { "JSON object keys must be strings" }
                key to item
            }
            encodeObject(stringMap)
        }
        else -> error("Unsupported canonical JSON value: ${value::class.java.name}")
    }
}
