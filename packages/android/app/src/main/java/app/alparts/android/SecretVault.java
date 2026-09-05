package app.alparts.android;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Only ciphertext leaves Android Keystore. Bind each value to its origin and name. */
final class SecretVault {
    private final SharedPreferences values;
    private final SecretKey key;
    SecretVault(Context context) throws Exception {
        values = context.getSharedPreferences("vault", Context.MODE_PRIVATE);
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        String alias = "alparts.local.v1";
        if (!store.containsAlias(alias)) {
            KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).setRandomizedEncryptionRequired(true).setUnlockedDeviceRequired(true).build());
            generator.generateKey();
        }
        key = (SecretKey) store.getKey(alias, null);
    }
    private String id(String origin, String name) {
        if (!name.matches("[A-Za-z0-9:_./-]{1,240}")) throw new IllegalArgumentException("INVALID_SECRET_NAME");
        return origin + "\n" + name;
    }
    synchronized String get(String origin, String name) throws Exception {
        String id = id(origin, name);
        String encoded = values.getString(id, null);
        if (encoded == null) return null;
        byte[] data = Base64.decode(encoded, Base64.NO_WRAP);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, data, 0, 12));
        cipher.updateAAD(id.getBytes(StandardCharsets.UTF_8));
        return new String(cipher.doFinal(data, 12, data.length - 12), StandardCharsets.UTF_8);
    }
    synchronized void set(String origin, String name, String value) throws Exception {
        String id = id(origin, name);
        if (value.length() > 32768 || (!values.contains(id) && values.getAll().size() >= 4096)) {
            throw new IllegalArgumentException("VAULT_CAPACITY");
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipher.updateAAD(id.getBytes(StandardCharsets.UTF_8));
        byte[] ciphertext = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
        byte[] combined = new byte[12 + ciphertext.length];
        System.arraycopy(cipher.getIV(), 0, combined, 0, 12);
        System.arraycopy(ciphertext, 0, combined, 12, ciphertext.length);
        if (!values.edit().putString(id, Base64.encodeToString(combined, Base64.NO_WRAP)).commit()) {
            throw new IllegalStateException("VAULT_WRITE_FAILED");
        }
    }
    synchronized void delete(String origin, String name) {
        if (!values.edit().remove(id(origin, name)).commit()) throw new IllegalStateException("VAULT_WRITE_FAILED");
    }
}
