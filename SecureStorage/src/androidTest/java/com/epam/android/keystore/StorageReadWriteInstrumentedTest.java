package com.epam.android.keystore;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static com.epam.android.keystore.SecureStorage.KEY_ALIAS;
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
public class StorageReadWriteInstrumentedTest {
    private SecureStorage storage;

    @Before
    public void before() {
        Context context = InstrumentationRegistry.getTargetContext();
        storage = new SecureStorage(context, KEY_ALIAS);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentException() throws Exception {
        storage.get(null);
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
        storage.set("key1", "passWORD");
        assertEquals("passWORD", storage.get("key1"));
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
    }

    @Test
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
    public void shouldClearKeys() throws Exception {
        storage.set("KEY", "1");
        storage.set("KEY2", "2");
        storage.clear("KEY");
        assertEquals("2", storage.get("KEY2"));
        storage.erase();
        assertNull(storage.get("KEY2"));
    }

    @Test
    public void emptyValueShouldReturnEmpty() throws Exception {
        storage.set("KEY", "");
        assertEquals("", storage.get("KEY"));
    }
}
