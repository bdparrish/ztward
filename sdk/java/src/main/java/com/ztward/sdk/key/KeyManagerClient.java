package com.ztward.sdk.key;

import com.google.protobuf.Timestamp;
import com.ztward.sdk.client.BearerTokenCallCredentials;
import com.ztward.sdk.client.TokenProvider;
import key_manager.KeyManagerServiceGrpc;
import key_manager.KeyManager;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

public final class KeyManagerClient {
    private final KeyManagerServiceGrpc.KeyManagerServiceBlockingStub stub;

    public KeyManagerClient(io.grpc.ManagedChannel channel, TokenProvider tokenProvider) {
        this.stub = KeyManagerServiceGrpc.newBlockingStub(channel)
                .withCallCredentials(new BearerTokenCallCredentials(tokenProvider));
    }

    public KeyMetadata registerKey(String clientId, byte[] publicKeyPem, Instant expiresAt) {
        System.err.println("[KeyManagerClient] registerKey request for clientId=" + clientId + ", expires=" + expiresAt);
        KeyManager.RegisterClientKeyRequest request = KeyManager.RegisterClientKeyRequest.newBuilder()
                .setClientId(clientId)
                .setPublicKeyPem(new String(publicKeyPem, StandardCharsets.US_ASCII))
                .setKeyType(KeyManager.KeyType.KEY_TYPE_RSA_2048)
                .setExpiresAt(Timestamp.newBuilder()
                        .setSeconds(expiresAt.getEpochSecond())
                        .setNanos(expiresAt.getNano())
                        .build())
                .build();
        KeyManager.RegisterClientKeyResponse response = stub.registerClientKey(request);
        System.err.println("[KeyManagerClient] registerKey response keyId=" + response.getKey().getKeyId());
        return new KeyMetadata(
                response.getKey().getKeyId(),
                Instant.now(),
                expiresAt
        );
    }

    /**
     * Reports whether Key Manager still holds keyId as an active key of the caller.
     * Unknown, foreign or inactive keys return false so a fresh key can be registered;
     * RPC failures propagate, so an outage never triggers re-registration.
     */
    public boolean isKeyUsable(String clientId, String keyId) {
        KeyManager.GetClientKeyResponse response = stub.getClientKey(KeyManager.GetClientKeyRequest.newBuilder()
                .setClientId(clientId)
                .setKeyId(keyId)
                .build());
        return response.getFound() && response.getKey().getStatus() == KeyManager.KeyStatus.KEY_STATUS_ACTIVE;
    }
}
