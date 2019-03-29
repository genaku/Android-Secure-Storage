package com.epam.android.keystore;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static com.epam.android.keystore.StringExtKt.toUtf8ByteArray;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;

/**
 * Instrumented test, which will execute on an Android device.
 * This test need launch in two devices for 18 - 22 and 23-27 version API
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class ThemisReadWriteInstrumentedTest {
    private ISecureStorage storage;

    @Before
    public void before() {
        Context context = InstrumentationRegistry.getTargetContext();
        storage = new ThemisSecureStorage(context, "0");
    }

    @Test
    public void shouldGetNullValueIfNotSet() throws Exception {
        String value = storage.get("blabla");
        assertNull(value);
    }

    @Test
    public void shouldSaveValue() throws Exception {
        storage.set("key", "passWORD");
        assertEquals("passWORD", storage.get("key"));
    }

    @Test
    public void shouldSaveOtherKeyValue() throws Exception {
        storage.set("key", "value");
        storage.set("key", "value1");
        storage.set("key", "value2");
        assertEquals("value2", storage.get("key"));
    }

    @Test
    public void shouldSaveOtherKeyValue2() throws Exception {
        storage.set("key1", "passWORD");
        assertEquals("passWORD", storage.get("key1"));
        storage.set("key2", "passWORD");
        assertEquals("passWORD", storage.get("key2"));
        assertEquals("passWORD", storage.get("key1"));
        storage.get("key1");
        assertEquals("passWORD", storage.get("key2"));
        assertEquals("passWORD", storage.get("key1"));
    }

    @Test
    public void shouldClearStorage() throws Exception {
        storage.set("key12", "1");
        assertEquals("1", storage.get("key12"));
        storage.clear("key12");
        assertNull(storage.get("key12"));
        storage.set("key13", "3456");
        storage.set("key14", "abc");
        storage.clear("key14");
        assertNull(storage.get("key14"));
        assertEquals("3456", storage.get("key13"));
    }

    //@Test
    public void shouldEraseValues() throws Exception {
        storage.set("key123", "12093qqwoiejqow812312312123poqj[ 9wpe7nrpwiercwe9rucpn[w9e7rnc;lwiehr pb8ry");
        assertEquals("12093qqwoiejqow812312312123poqj[ 9wpe7nrpwiercwe9rucpn[w9e7rnc;lwiehr pb8ry", storage.get("key123"));
        storage.erase();
        assertNotEquals("12093qqwoiejqow812312312123poqj[ 9wpe7nrpwiercwe9rucpn[w9e7rnc;lwiehr pb8ry", storage.get("key123"));
        assertNull(storage.get("key123"));
    }

    @Test
    public void shouldReturnNullIfNoKeyWithWhitespaces() throws Exception {
        assertNull(storage.get("bad key"));
    }

    @Test
    public void shouldSaveValueForKeyWithWhitespaces() throws Exception {
        storage.set("KEY", "@");
        assertNull(storage.get("bad key"));
    }

    @Test
    public void shouldClearForKey() throws Exception {
        storage.set("KEY", "@");
        storage.clear("KEY");
        assertNull(storage.get("KEY"));
    }

    @Test
    public void emptyValueShouldThrowException() throws Exception {
        storage.set("KEY", "");
        assertEquals("", storage.get("KEY"));
    }

    @Test
    public void emptyValue() {
        assertArrayEquals("".getBytes(), toUtf8ByteArray(""));
    }

    //@Test
    public void shouldClearKeys() throws Exception {
        storage.set("KEY", "1");
        storage.set("KEY2", "2");
        storage.set("KEY3", "3");
        storage.set("KEY4", "4");
        storage.clear("KEY");
        assertEquals("2", storage.get("KEY2"));
        storage.erase();
        assertNull(storage.get("KEY2"));
        assertNull(storage.get("KEY2"));
        assertNull(storage.get("KEY3"));
        assertNull(storage.get("KEY4"));
    }
}
