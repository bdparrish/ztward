package com.ztward.sdk.client;

import java.util.concurrent.CompletableFuture;

@FunctionalInterface
public interface TokenProvider {
    CompletableFuture<String> getToken();
}
