package com.cryptopp.keystorersa;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Calendar;

import javax.crypto.KeyGenerator;
import javax.security.auth.x500.X500Principal;

import android.util.Log;


public class EncryptionKeyGenerator {
    //public final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private final String KEY_STORE_FILE_NAME = "KEY_STORE";
    private final String KEY_STORE_PASSWORD = "KEY_STORE_PASSWORD";
    public static String KEY_ALIAS;

    public static String getKeyAlias() {
        return KEY_ALIAS;
    }

    public static void setKeyAlias(String keyAlias) {
        EncryptionKeyGenerator.KEY_ALIAS = keyAlias;
    }



    @TargetApi(Build.VERSION_CODES.M) public SecurityKey generateSecretKey(KeyStore keyStore) {
        try {
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                KeyGenerator keyGenerator =
                        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setIsStrongBoxBacked(true)
                            .setRandomizedEncryptionRequired(false)
                            .build() );

                }

                return new SecurityKey(keyGenerator.generateKey());

            }


        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | KeyStoreException  e) {
            e.printStackTrace();
        }


        try {
            final KeyStore.SecretKeyEntry entry =
                    (KeyStore.SecretKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
            return new SecurityKey(entry.getSecretKey());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
        }
        return null;
    }


    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public SecurityKey generateKeyPairPreM(Context context, KeyStore keyStore) {

        try {
            if (!keyStore.containsAlias(KEY_ALIAS)) {

                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                //1 Year validity
                end.add(Calendar.YEAR, 1);
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context).setAlias(KEY_ALIAS)
                        .setSubject(new X500Principal("CN=" + KEY_ALIAS))
                        .setSerialNumber(BigInteger.TEN)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();


                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                kpg.initialize(spec);
                kpg.generateKeyPair();
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
            e.printStackTrace();
        }

        try {
            final KeyStore.PrivateKeyEntry entry =
                    (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
            return new SecurityKey(
                    new KeyPair(entry.getCertificate().getPublicKey(), entry.getPrivateKey()));
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        return null;
    }

    public SecurityKey generateSecretKeyPre18(Context context) {

        try {
            KeyStore androidCAStore = KeyStore.getInstance(KeyStore.getDefaultType());

            char[] password = KEY_STORE_PASSWORD.toCharArray();

            boolean isKeyStoreLoaded = loadKeyStore(context, androidCAStore, password);
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);
            if (!isKeyStoreLoaded || !androidCAStore.containsAlias(KEY_ALIAS)) {
                //Create and save new secret key
                saveMyKeystore(context, androidCAStore, password, protParam);
            }

            // Fetch Secret Key
            KeyStore.SecretKeyEntry pkEntry =
                    (KeyStore.SecretKeyEntry) androidCAStore.getEntry(KEY_ALIAS, protParam);

            return new SecurityKey(pkEntry.getSecretKey());
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();

        }
        return null;
    }

    private boolean loadKeyStore(Context context, KeyStore androidCAStore,
                                 char[] password) {
        java.io.FileInputStream fis;
        try {
            fis = context.openFileInput(KEY_STORE_FILE_NAME);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return false;
        }
        try {
            androidCAStore.load(fis, password);
            return true;
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        }
        return false;
    }

    private void saveMyKeystore(Context context, KeyStore androidCAStore,
                                char[] password,
                                KeyStore.ProtectionParameter protParam)
            throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException {

        javax.crypto.SecretKey mySecretKey = KeyGenerator.getInstance("AES").generateKey();
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(mySecretKey);
        androidCAStore.load(null);
        androidCAStore.setEntry(KEY_ALIAS, skEntry, protParam);
        java.io.FileOutputStream fos = null;
        try {
            fos = context.openFileOutput(KEY_STORE_FILE_NAME, Context.MODE_PRIVATE);

            androidCAStore.store(fos, password);
        } finally {
            if (fos != null) {
                fos.close();
            }
        }
    }
}