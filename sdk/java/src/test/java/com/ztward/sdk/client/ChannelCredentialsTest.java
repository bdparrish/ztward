package com.ztward.sdk.client;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.grpc.InsecureChannelCredentials;
import io.grpc.TlsChannelCredentials;
import java.net.URI;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ChannelCredentialsTest {

    @Test
    void httpUsesPlaintext() {
        assertInstanceOf(InsecureChannelCredentials.class,
                ZtwardClient.channelCredentials(URI.create("http://localhost:50053"), null));
    }

    @Test
    void httpsUsesTlsWithDefaultTrust() {
        assertInstanceOf(TlsChannelCredentials.class,
                ZtwardClient.channelCredentials(URI.create("https://localhost:50053"), null));
    }

    @Test
    void unreadableCaFileFailsInsteadOfDowngrading(@TempDir Path dir) {
        String missing = dir.resolve("missing.pem").toString();
        assertThrows(IllegalStateException.class,
                () -> ZtwardClient.channelCredentials(URI.create("https://localhost:50053"), missing));
    }
}
