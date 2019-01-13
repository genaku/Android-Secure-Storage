package com.epam.android.keystore;

import java.security.KeyStoreException;

public class SecureStorage {
    static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    static final String KEY_ALIAS = "aliaskeystore";
    private SensitiveInfoModule versionStrategy;

    public void setStrategy(SensitiveInfoModule strategy) {
        this.versionStrategy = strategy;
    }

    public void save(String key, String value) throws SecureStorageException {
        versionStrategy.save(key, value);
    }

    public String get(String key) throws SecureStorageException {
        return versionStrategy.get(key);
    }

    public void clear(String key) {
        versionStrategy.clear(key);
    }

    public void erase() throws KeyStoreException {
        versionStrategy.erase();
    }
}
