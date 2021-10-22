package com.cryptopp.keystorersa;


import android.content.Context;
import android.os.Build;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class EncryptionUtils {
    public static String encrypt(Context context, String token) {
        SecurityKey securityKey = getSecurityKey(context);
        return securityKey != null ? securityKey.encrypt(token) : null;
    }

    public static String decrypt(Context context, String token) {
        SecurityKey securityKey = getSecurityKey(context);
        return securityKey != null ? securityKey.decrypt(token) : null;
    }

    private static SecurityKey getSecurityKey(Context context) {
        EncryptionKeyGenerator encryptionKeyGenerator = new EncryptionKeyGenerator();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return encryptionKeyGenerator.generateSecretKey(getKeyStore());
        }
//     else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
//        return encryptionKeyGenerator.generateKeyPairPreM(context, getKeyStore());
//    }

        else {
        return encryptionKeyGenerator.generateKeyPairPreM(context, getKeyStore());//generateSecretKeyPre18(context);
    }
}

    private static KeyStore getKeyStore() {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        return keyStore;
    }

    public static void clear() {
        EncryptionKeyGenerator encryptionKeyGenerator = new EncryptionKeyGenerator();
        KeyStore keyStore = getKeyStore();
        try {
            if (keyStore.containsAlias(encryptionKeyGenerator.KEY_ALIAS)) {
                keyStore.deleteEntry(encryptionKeyGenerator.KEY_ALIAS);
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }
}