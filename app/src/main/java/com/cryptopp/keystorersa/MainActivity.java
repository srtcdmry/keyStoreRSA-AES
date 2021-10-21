package com.cryptopp.keystorersa;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;


public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Button encrptButton = findViewById(R.id.encryptButton);
        Button decrypButton = findViewById(R.id.decryptButton);
        EditText plainText = findViewById(R.id.plainText);
        TextView encryptResult = findViewById(R.id.encryptedText);
        TextView decryptResult = findViewById(R.id.decryptedText);
        encrptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String encryptedValue = EncryptionUtils.encrypt(getApplicationContext(), plainText.getText().toString());
                Log.v(" Encrypted Value : ", encryptedValue);
                encryptResult.setText(encryptedValue);

                decrypButton.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {
                        String decryptedValue = EncryptionUtils.decrypt(getApplicationContext(), encryptedValue);
                        Log.v(" Decrypted Value : ", decryptedValue);
                        decryptResult.setText(decryptedValue);
                    }
                });
            }
        });
    }
}