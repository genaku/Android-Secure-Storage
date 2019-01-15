package com.epam.android.keystore.demo;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import com.epam.android.keystore.SecureStorage;
import com.epam.android.keystore.SecureStorageException;

import butterknife.BindView;
import butterknife.ButterKnife;

public class MainActivity extends AppCompatActivity {

    @BindView(R.id.tv_decrypted_value)
    TextView tvDecryptedValue;

    @BindView(R.id.tv_stored_value)
    TextView tvStoredValue;

    @BindView(R.id.et_value_to_store)
    EditText etToBeStored;

    private SecureStorage storage;
    private final String TEST_KEY = "password";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ButterKnife.bind(this);

        try {
            storage = new SecureStorage(this, "myalias");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void saveValue(View view) throws SecureStorageException {
        if (storage != null) {
            storage.set(TEST_KEY, etToBeStored.getText().toString());
        }
    }

    public void getDecryptedValue(View view) throws SecureStorageException {
        if (storage != null) {
            tvDecryptedValue.setText(storage.get(TEST_KEY));
        }
    }

    public void getStoredValue(View view) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        tvStoredValue.setText(prefs.getString(TEST_KEY, ""));
    }

}
