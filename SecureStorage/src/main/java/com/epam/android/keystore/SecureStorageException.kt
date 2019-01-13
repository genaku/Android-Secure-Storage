package com.epam.android.keystore

/**
 * Created by Andrei_Gusenkov on 3/13/2018.
 */

class SecureStorageException : Exception {
    constructor() : super() {}
    constructor(message: String) : super(message) {}
    constructor(message: String, cause: Throwable) : super(message, cause) {}
    constructor(cause: Throwable) : super(cause) {}
}
