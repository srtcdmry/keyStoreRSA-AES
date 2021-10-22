package com.cryptopp.keystorersa;

import androidx.appcompat.app.AppCompatActivity;

import android.content.pm.PackageManager;
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
        EditText aliasText = findViewById(R.id.alias);
        TextView encryptResult = findViewById(R.id.encryptedText);
        TextView decryptResult = findViewById(R.id.decryptedText);
        EncryptionKeyGenerator encryptionKeyGenerator = new EncryptionKeyGenerator();

        boolean hasStrongBox;
        hasStrongBox = getApplicationContext().getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
System.out.println("hasstrong " + hasStrongBox);
        encrptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                encryptionKeyGenerator.setKeyAlias(aliasText.getText().toString());
                String encryptedValue = EncryptionUtils.encrypt(getApplicationContext(), plainText.getText().toString());
                encryptResult.setText(encryptedValue);
                System.out.println("ENC : " + encryptedValue);
                decrypButton.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {
                        String decryptedValue = EncryptionUtils.decrypt(getApplicationContext(), encryptedValue);
                        decryptResult.setText(decryptedValue);
                    }
                });
            }
        });
    }
}