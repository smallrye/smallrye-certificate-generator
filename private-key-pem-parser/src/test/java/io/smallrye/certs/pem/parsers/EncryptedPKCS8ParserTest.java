package io.smallrye.certs.pem.parsers;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EncryptedPKCS8ParserTest {

    private PrivateKey originalPrivateKey;
    private EncryptedPKCS8Parser parser;
    private String encryptedPKCS8Key;
    private static final String password = "correctPassword";
    private Provider[] providers;

    @BeforeEach
    void setup() throws Exception {
        providers = Security.getProviders();
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        originalPrivateKey = keyGen.generateKeyPair().getPrivate();

        try (StringWriter writer = new StringWriter();
                JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {

            // Define the encryptor with desired algorithm and passphrase
            OutputEncryptor encryptor = new JceOpenSSLPKCS8EncryptorBuilder(
                    PKCS8Generator.PBE_SHA1_3DES).setPassword(password.toCharArray()).build();

            // Create an encrypted PKCS8 format
            PKCS8Generator pkcs8Generator = new JcaPKCS8Generator(originalPrivateKey, encryptor);

            // Write the encrypted private key to a file in PEM format
            pemWriter.writeObject(pkcs8Generator);
            pemWriter.close();
            encryptedPKCS8Key = writer.toString();
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
        parser = new EncryptedPKCS8Parser();
    }

    @AfterEach
    void restoreProviders() {
        for (Provider provider : Security.getProviders()) {
            Security.removeProvider(provider.getName());
        }
        for (Provider provider : providers) {
            Security.addProvider(provider);
        }
    }

    @Test
    void testParseValidEncryptedKeyWithCorrectPassword() {
        PrivateKey privateKey = parser.getKey(encryptedPKCS8Key, password);
        assertNotNull(privateKey, "Private key should not be null with correct password");
    }

    @Test
    void testParseValidEncryptedKeyWithIncorrectPassword() {
        String incorrectPassword = "wrongPassword";
        PrivateKey privateKey = parser.getKey(encryptedPKCS8Key, incorrectPassword);
        assertNull(privateKey, "Private key should be null with incorrect password");
    }

    @Test
    void testParseInvalidEncryptedKeyFormat() {
        String invalidKey = """
                -----BEGIN ENCRYPTED PRIVATE KEY-----
                InvalidBase64Data==
                -----END ENCRYPTED PRIVATE KEY-----
                """;
        PrivateKey privateKey = parser.getKey(invalidKey, password);
        assertNull(privateKey, "Private key should be null for invalid key format");
    }

    @Test
    void testParseNonEncryptedRandomKey() {
        String nonEncryptedKey = """
                -----BEGIN PRIVATE KEY-----
                MIIBVgIBADANBgkqhkiG9w0BAQEFAASCATwwggE4AgEAAkEA...moreBase64Data...==
                -----END PRIVATE KEY-----
                """;
        PrivateKey privateKey = parser.getKey(nonEncryptedKey, password);
        assertNull(privateKey, "Private key should be null for non-encrypted key");
    }

    @Test
    void testParseValidEncryptedPkcs8Key() {
        PrivateKey decryptedKey = parser.getKey(encryptedPKCS8Key, password);
        assertNotNull(decryptedKey, "Decrypted private key should not be null for a valid encrypted PKCS8 key");
    }

    @Test
    void testParseWithIncorrectPassword() {
        PrivateKey decryptedKey = parser.getKey(encryptedPKCS8Key, "wrongPassword");
        assertNull(decryptedKey, "Decrypted private key should be null when an incorrect password is used");
    }

    @Test
    void testDecryptedKeyAttributesMatchOriginal() throws Exception {
        PrivateKey decryptedKey = parser.getKey(encryptedPKCS8Key, password);
        assertNotNull(decryptedKey, "Decrypted private key should not be null for a valid encrypted PKCS8 key");

        // Verify that the decrypted key and original key are of the same type and have the same attributes
        assertEquals(originalPrivateKey.getAlgorithm(), decryptedKey.getAlgorithm(),
                "Algorithm should match original private key");
        assertArrayEquals(originalPrivateKey.getEncoded(), decryptedKey.getEncoded(),
                "Decrypted key should match the original private key in encoding");
    }

    @Test
    void testParseNonEncryptedKey() {
        String nonEncryptedPem = Base64.getEncoder().encodeToString(originalPrivateKey.getEncoded());
        String nonEncryptedKeyPem = """
                -----BEGIN PRIVATE KEY-----
                %s
                -----END PRIVATE KEY-----
                """.formatted(nonEncryptedPem);

        PrivateKey decryptedKey = parser.getKey(nonEncryptedKeyPem, password);
        assertNull(decryptedKey, "Parsed private key should be null for a non-encrypted PKCS8 PEM format");
    }

    @Test
    void testGetKeyOrFailWithCorrectPassword() {
        PrivateKey decryptedKey = parser.getKeyOrFail(encryptedPKCS8Key, password);
        assertArrayEquals(originalPrivateKey.getEncoded(), decryptedKey.getEncoded());
        assertEquals(parser.decryptKey(encryptedPKCS8Key, password).toString(),
                parser.decryptKeyOrFail(encryptedPKCS8Key, password).toString());
    }

    @Test
    void testGetKeyOrFailWithIncorrectPassword() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> parser.getKeyOrFail(encryptedPKCS8Key, "wrongPassword"));
        assertTrue(e.getMessage().contains("the secret is probably wrong"), e.getMessage());
        assertInstanceOf(GeneralSecurityException.class, e.getCause());
        assertThrows(IllegalArgumentException.class, () -> parser.decryptKeyOrFail(encryptedPKCS8Key, "wrongPassword"));
    }

    @Test
    void testGetKeyOrFailWithUnavailableEncryptionAlgorithm() throws Exception {
        String key;
        try (StringWriter writer = new StringWriter(); JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            OutputEncryptor encryptor = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_2DES)
                    .setPassword(password.toCharArray()).build();
            pemWriter.writeObject(new JcaPKCS8Generator(originalPrivateKey, encryptor));
            pemWriter.close();
            key = writer.toString();
        }
        assertNotNull(parser.getKey(key, password), "The key can be decrypted while BouncyCastle is installed");

        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> parser.getKeyOrFail(key, password));
        assertTrue(e.getMessage().contains("is not available from the installed security providers"), e.getMessage());
        assertInstanceOf(NoSuchAlgorithmException.class, e.getCause());
        assertNull(parser.getKey(key, password));
    }

    @Test
    void testGetKeyOrFailWithMalformedKey() {
        String invalidKey = """
                -----BEGIN ENCRYPTED PRIVATE KEY-----
                InvalidBase64Data==
                -----END ENCRYPTED PRIVATE KEY-----
                """;
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> parser.getKeyOrFail(invalidKey, password));
        assertTrue(e.getMessage().contains("malformed"), e.getMessage());
        assertNotNull(e.getCause());
    }

    @Test
    void testGetKeyOrFailWithNonEncryptedKey() {
        String nonEncryptedKeyPem = """
                -----BEGIN PRIVATE KEY-----
                %s
                -----END PRIVATE KEY-----
                """.formatted(Base64.getEncoder().encodeToString(originalPrivateKey.getEncoded()));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> parser.getKeyOrFail(nonEncryptedKeyPem, password));
        assertTrue(e.getMessage().contains("Not an encrypted PKCS#8 key"), e.getMessage());
    }
}
