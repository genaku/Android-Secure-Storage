package com.epam.android.keystore

import android.support.test.InstrumentationRegistry
import android.support.test.runner.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented test, which will execute on an Android device.
 * This test need launch in two devices for 18 - 22 and 23-27 version API
 *
 * @see [Testing documentation](http://d.android.com/tools/testing)
 */
@RunWith(AndroidJUnit4::class)
class ThemisReadWriteInstrumentedTest {
    
    private lateinit var storage: ISecureStorage

    @Before
    fun before() {
        val context = InstrumentationRegistry.getTargetContext()
        storage = ThemisSecureStorage(context, "0")
    }

    @Test
    @Throws(Exception::class)
    fun shouldGetNullValueIfNotSet() {
        val value = storage["blabla"]
        assertNull(value)
    }

    @Test
    @Throws(Exception::class)
    fun shouldSaveValue() {
        storage.set("key", "passWORD")
        assertEquals("passWORD", storage["key"])
    }

    @Test
    @Throws(Exception::class)
    fun shouldSaveOtherKeyValue() {
        storage.set("key", "value")
        storage.set("key", "value1")
        storage.set("key", "value2")
        assertEquals("value2", storage["key"])
    }

    @Test
    @Throws(Exception::class)
    fun shouldSaveOtherKeyValue2() {
        storage.set("key1", "passWORD")
        assertEquals("passWORD", storage["key1"])
        storage.set("key2", "passWORD")
        assertEquals("passWORD", storage["key2"])
        assertEquals("passWORD", storage["key1"])
        storage["key1"]
        assertEquals("passWORD", storage["key2"])
        assertEquals("passWORD", storage["key1"])
    }

    @Test
    @Throws(Exception::class)
    fun shouldStoreBigLengthValue() {
        val expectedString = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
        storage.set("key1", expectedString)
        assertEquals(expectedString, storage["key1"])
    }

    @Test
    @Throws(Exception::class)
    fun shouldClearStorage() {
        storage.set("key12", "1")
        assertEquals("1", storage["key12"])
        storage.clear("key12")
        assertNull(storage["key12"])
        storage.set("key13", "3456")
        storage.set("key14", "abc")
        storage.clear("key14")
        assertNull(storage["key14"])
        assertEquals("3456", storage["key13"])
    }

    //@Test
    @Throws(Exception::class)
    fun shouldEraseValues() {
        storage.set("key123", "12093qqwoiejqow812312312123poqj[ 9wpe7nrpwiercwe9rucpn[w9e7rnc;lwiehr pb8ry")
        assertEquals("12093qqwoiejqow812312312123poqj[ 9wpe7nrpwiercwe9rucpn[w9e7rnc;lwiehr pb8ry", storage["key123"])
        storage.erase()
        assertNotEquals("12093qqwoiejqow812312312123poqj[ 9wpe7nrpwiercwe9rucpn[w9e7rnc;lwiehr pb8ry", storage["key123"])
        assertNull(storage["key123"])
    }

    @Test
    @Throws(Exception::class)
    fun shouldReturnNullIfNoKeyWithWhitespaces() {
        assertNull(storage["bad key"])
    }

    @Test
    @Throws(Exception::class)
    fun shouldSaveValueForKeyWithWhitespaces() {
        storage.set("KEY", "@")
        assertNull(storage["bad key"])
    }

    @Test
    @Throws(Exception::class)
    fun shouldClearForKey() {
        storage.set("KEY", "@")
        storage.clear("KEY")
        assertNull(storage["KEY"])
    }

    @Test
    @Throws(Exception::class)
    fun emptyValueShouldThrowException() {
        storage.set("KEY", "")
        assertEquals("", storage["KEY"])
    }

    @Test
    fun emptyValue() {
        assertArrayEquals("".toByteArray(), "".toUtf8ByteArray())
    }

    //@Test
    @Throws(Exception::class)
    fun shouldClearKeys() {
        storage.set("KEY", "1")
        storage.set("KEY2", "2")
        storage.set("KEY3", "3")
        storage.set("KEY4", "4")
        storage.clear("KEY")
        assertEquals("2", storage["KEY2"])
        storage.erase()
        assertNull(storage["KEY2"])
        assertNull(storage["KEY2"])
        assertNull(storage["KEY3"])
        assertNull(storage["KEY4"])
    }
}
