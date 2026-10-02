package io.smallrye.certs.pem.parsers;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PKCS8ParserTest {

    private PKCS8Parser parser;
    private PrivateKey originalPrivateKey;
    private String pkcs8PemKey;

    @BeforeEach
    void setup() throws Exception {
        // Add BouncyCastle provider for additional algorithms if needed
        Security.addProvider(new BouncyCastleProvider());

        // Initialize the parser
        parser = new PKCS8Parser();

        // Step 1: Generate an RSA key pair and store the original private key
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        originalPrivateKey = keyPair.getPrivate();

        // Step 2: Convert the private key to PKCS#8 format and encode it as a PEM string
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(originalPrivateKey.getEncoded());
        byte[] pkcs8EncodedKey = pkcs8KeySpec.getEncoded();
        String base64EncodedKey = Base64.getMimeEncoder().encodeToString(pkcs8EncodedKey);
        pkcs8PemKey = "-----BEGIN PRIVATE KEY-----\n" + base64EncodedKey + "\n-----END PRIVATE KEY-----";
    }

    @Test
    void testParseValidPkcs8Key() {
        // Parse the PKCS8 PEM key using PKCS8Parser
        PrivateKey parsedKey = parser.getKey(pkcs8PemKey, null);
        assertNotNull(parsedKey, "Parsed private key should not be null for a valid PKCS8 PEM key");

        // Verify algorithm and format
        assertEquals(originalPrivateKey.getAlgorithm(), parsedKey.getAlgorithm(),
                "Algorithm should match the original private key");
        assertEquals(originalPrivateKey.getFormat(), parsedKey.getFormat(), "Format should be PKCS#8");

        // Verify the encoded key bytes to ensure exact match
        assertArrayEquals(originalPrivateKey.getEncoded(), parsedKey.getEncoded(),
                "Parsed key should match the original private key in encoding");
    }

    @Test
    void testParseInvalidPkcs8KeyFormat() {
        // Test that an invalid PEM format is handled gracefully and returns null
        String invalidPemKey = "-----BEGIN PRIVATE KEY-----\nInvalidBase64Data==\n-----END PRIVATE KEY-----";
        PrivateKey parsedKey = parser.getKey(invalidPemKey, null);
        assertNull(parsedKey, "Parsed private key should be null for an invalid PEM format");
    }

    @Test
    void testParseNonPkcs8Key() {
        // Test that a non-PKCS8 key (e.g., an encrypted or unsupported format) returns null
        String nonPkcs8PemKey = """
                -----BEGIN ENCRYPTED PRIVATE KEY-----
                MIIBvTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIu7HB4LKl0xgCAggA
                ...
                -----END ENCRYPTED PRIVATE KEY-----
                """;
        PrivateKey parsedKey = parser.getKey(nonPkcs8PemKey, null);
        assertNull(parsedKey, "Parsed private key should be null for a non-PKCS8 format");
    }

    @Test
    void testGetKeyOrFail() {
        assertArrayEquals(originalPrivateKey.getEncoded(), parser.getKeyOrFail(pkcs8PemKey, null).getEncoded());
        String invalidPemKey = "-----BEGIN PRIVATE KEY-----\nInvalidBase64Data==\n-----END PRIVATE KEY-----";
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> parser.getKeyOrFail(invalidPemKey, null));
        assertTrue(e.getMessage().contains("PKCS8Parser"), e.getMessage());
    }
}