package com.ztward.sdk.key;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import key_manager.KeyManager;
import key_manager.KeyManagerServiceGrpc;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class KeyManagerClientTest {

    private Server server;
    private ManagedChannel channel;

    private KeyManagerClient clientAnswering(Supplier<KeyManager.GetClientKeyResponse> answer) throws Exception {
        String name = InProcessServerBuilder.generateName();
        server = InProcessServerBuilder.forName(name).directExecutor()
                .addService(new KeyManagerServiceGrpc.KeyManagerServiceImplBase() {
                    @Override
                    public void getClientKey(KeyManager.GetClientKeyRequest request,
                                             StreamObserver<KeyManager.GetClientKeyResponse> observer) {
                        try {
                            observer.onNext(answer.get());
                            observer.onCompleted();
                        } catch (StatusRuntimeException e) {
                            observer.onError(e);
                        }
                    }
                })
                .build().start();
        channel = InProcessChannelBuilder.forName(name).directExecutor().build();
        return new KeyManagerClient(channel, () -> CompletableFuture.completedFuture("token"));
    }

    private static KeyManager.GetClientKeyResponse found(KeyManager.KeyStatus status) {
        return KeyManager.GetClientKeyResponse.newBuilder()
                .setFound(true)
                .setKey(KeyManager.Key.newBuilder().setKeyId("k1").setStatus(status))
                .build();
    }

    @AfterEach
    void tearDown() {
        if (channel != null) channel.shutdownNow();
        if (server != null) server.shutdownNow();
    }

    @Test
    void activeKeyIsUsable() throws Exception {
        assertTrue(clientAnswering(() -> found(KeyManager.KeyStatus.KEY_STATUS_ACTIVE)).isKeyUsable("c1", "k1"));
    }

    @Test
    void unknownKeyIsNotUsable() throws Exception {
        KeyManager.GetClientKeyResponse notFound = KeyManager.GetClientKeyResponse.newBuilder().setFound(false).build();
        assertFalse(clientAnswering(() -> notFound).isKeyUsable("c1", "k1"));
    }

    @Test
    void revokedKeyIsNotUsable() throws Exception {
        assertFalse(clientAnswering(() -> found(KeyManager.KeyStatus.KEY_STATUS_REVOKED)).isKeyUsable("c1", "k1"));
    }

    @Test
    void rpcFailureIsAnErrorNotAVerdict() throws Exception {
        KeyManagerClient client = clientAnswering(() -> {
            throw Status.UNAVAILABLE.asRuntimeException();
        });
        assertThrows(StatusRuntimeException.class, () -> client.isKeyUsable("c1", "k1"));
    }
}
