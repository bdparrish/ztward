package com.ztward.sdk.key;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileKeyStoreTest {

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static KeyMetadata metadata(String keyId) {
        Instant now = Instant.now();
        return new KeyMetadata(keyId, now, now.plus(1, ChronoUnit.DAYS));
    }

    @Test
    void roundTripsRawBase64Keys(@TempDir Path root) throws Exception {
        KeyPair pair = rsaKeyPair();
        FileKeyStore store = new FileKeyStore(root);
        store.saveKeyPair(metadata("raw"), pair.getPublic(), pair.getPrivate());

        Optional<StoredKeyPair> loaded = store.getLatestKey();

        assertTrue(loaded.isPresent());
        assertArrayEquals(pair.getPrivate().getEncoded(), loaded.get().getPrivateKey().getEncoded());
    }

    @Test
    void loadsPemArmoredKeys(@TempDir Path root) throws Exception {
        KeyPair pair = rsaKeyPair();
        FileKeyStore store = new FileKeyStore(root);
        store.saveKeyPair(metadata("pem"), pair.getPublic(), pair.getPrivate());
        String armored = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pair.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        Files.writeString(root.resolve("pem").resolve("private.pem"), armored);

        Optional<StoredKeyPair> loaded = store.getLatestKey();

        assertTrue(loaded.isPresent());
        assertArrayEquals(pair.getPrivate().getEncoded(), loaded.get().getPrivateKey().getEncoded());
    }
}
