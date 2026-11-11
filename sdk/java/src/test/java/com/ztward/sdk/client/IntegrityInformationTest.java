package com.ztward.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class IntegrityInformationTest {

    @Test
    void singlePayloadIntegrityMatchesGoAndJsShape() {
        Map<String, Object> integrity = ZtwardClient.integrityInformation("aGFzaA==", 28, 44);

        assertEquals("SHA256", integrity.get("segmentHashAlg"));
        assertEquals(Map.of("alg", "SHA256", "sig", "aGFzaA=="), integrity.get("rootSignature"));
        assertEquals(
                List.of(Map.of("hash", "aGFzaA==", "segmentSize", 28, "encryptedSegmentSize", 44)),
                integrity.get("segments"));
    }

    @Test
    void noIntegrityWhenHashDisabled() {
        assertNull(ZtwardClient.integrityInformation(null, 28, 44));
    }
}
