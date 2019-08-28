package com.epam.android.keystore

fun String.toUtf8ByteArray() =
        this.toByteArray(UTF8_CHARSET)

val UTF8_CHARSET = charset("UTF-8")

