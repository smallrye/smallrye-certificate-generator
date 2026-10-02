package io.smallrye.certs.pem.parsers;

import io.vertx.core.buffer.Buffer;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EncryptedPKCS8Parser implements PKPemParser {

    private static final String PKCS8_ENCRYPTED_START = "-+BEGIN\\s+ENCRYPTED\\s+PRIVATE\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+";

    private static final String PKCS8_ENCRYPTED_END = "-+END\\s+ENCRYPTED\\s+PRIVATE\\s+KEY[^-]*-+";

    private static final Pattern PATTERN = Pattern.compile(PKCS8_ENCRYPTED_START + BASE64_TEXT + PKCS8_ENCRYPTED_END,
            Pattern.CASE_INSENSITIVE);

    private static final List<String> ALGORITHMS = List.of("RSA", "RSASSA-PSS", "EC", "DSA", "EdDSA", "XDH");

    public static final String PBES2_ALGORITHM = "PBES2";

    public EncryptedPKCS8Parser() {
    }

    /**
     * Extracts the private key from the encrypted PKCS#8 format.
     *
     * @param content the encrypted PKCS#8 content
     * @param secret the secret to decrypt the key
     * @return the private key or {@code null} if the content is not a PKCS#8 encrypted key
     */
    @Override
    public PrivateKey getKey(String content, String secret) {
        try {
            return getKeyOrFail(content, secret);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extracts the private key from the encrypted PKCS#8 format, and reports why when it cannot.
     *
     * @param content the encrypted PKCS#8 content
     * @param secret the secret to decrypt the key
     * @return the private key, never {@code null}
     * @throws IllegalArgumentException if the content is not a PKCS#8 encrypted key, is malformed, is encrypted with
     *         an algorithm that is not available, or cannot be decrypted with the given secret
     */
    @Override
    public PrivateKey getKeyOrFail(String content, String secret) {
        Matcher matcher = PATTERN.matcher(content);
        if (!matcher.find()) {
            throw new IllegalArgumentException("Not an encrypted PKCS#8 key: there is no 'ENCRYPTED PRIVATE KEY' block");
        }
        EncryptedPrivateKeyInfo keyInfo;
        try {
            keyInfo = new EncryptedPrivateKeyInfo(decodeBase64(matcher.group(BASE64_TEXT_GROUP)));
        } catch (IOException | IllegalArgumentException e) {
            throw new IllegalArgumentException("The encrypted PKCS#8 key is malformed", e);
        }
        var key = decrypt(keyInfo, secret);
        for (String algo : ALGORITHMS) {
            try {
                KeyFactory factory = KeyFactory.getInstance(algo);
                return factory.generatePrivate(key);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                // Ignore
            }
        }
        String algo = key.getAlgorithm();
        throw new IllegalArgumentException(algo != null
                ? "The algorithm of the decrypted key '" + algo + "' is not one of " + ALGORITHMS
                : "The algorithm of the decrypted key could not be determined and is not one of " + ALGORITHMS);
    }

    static PKCS8EncodedKeySpec decrypt(byte[] bytes, String secret) {
        try {
            return decrypt(new EncryptedPrivateKeyInfo(bytes), secret);
        } catch (IOException ex) {
            throw new IllegalArgumentException("Error decrypting private key", ex);
        }
    }

    private static PKCS8EncodedKeySpec decrypt(EncryptedPrivateKeyInfo keyInfo, String secret) {
        AlgorithmParameters algorithmParameters = keyInfo.getAlgParameters();
        String encryptionAlgorithm = getEncryptionAlgorithm(algorithmParameters, keyInfo.getAlgName());
        Cipher cipher;
        SecretKeyFactory keyFactory;
        try {
            keyFactory = SecretKeyFactory.getInstance(encryptionAlgorithm);
            cipher = Cipher.getInstance(encryptionAlgorithm);
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("The key is encrypted with '" + encryptionAlgorithm
                    + "', which is not available from the installed security providers", ex);
        }
        try {
            SecretKey key = keyFactory.generateSecret(new PBEKeySpec(secret.toCharArray()));
            cipher.init(Cipher.DECRYPT_MODE, key, algorithmParameters);
            return keyInfo.getKeySpec(cipher);
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Unable to decrypt the key encrypted with '" + encryptionAlgorithm
                    + "', the secret is probably wrong", ex);
        }
    }

    private static String getEncryptionAlgorithm(AlgorithmParameters algParameters, String algName) {
        if (algParameters != null && PBES2_ALGORITHM.equals(algName)) {
            return algParameters.toString();
        }
        return algName;
    }

    /**
     * Retrieves the private key as plain PKCS#8 from the encrypted PKCS#8 content.
     *
     * @param content the encrypted PKCS#8 content
     * @param secret the secret to decrypt the key
     * @return the decrypted PKCS#8 key or {@code null} if the content is not a PKCS#8 encrypted key
     */
    public Buffer decryptKey(String content, String secret) {
        var pk = getKey(content, secret);
        if (pk == null) {
            return null;
        }
        return toPem(pk);
    }

    /**
     * Retrieves the private key as plain PKCS#8 from the encrypted PKCS#8 content, and reports why when it cannot.
     *
     * @param content the encrypted PKCS#8 content
     * @param secret the secret to decrypt the key
     * @return the decrypted PKCS#8 key, never {@code null}
     * @throws IllegalArgumentException if the content is not a PKCS#8 encrypted key, is malformed, is encrypted with
     *         an algorithm that is not available, or cannot be decrypted with the given secret
     */
    public Buffer decryptKeyOrFail(String content, String secret) {
        return toPem(getKeyOrFail(content, secret));
    }

    private static Buffer toPem(PrivateKey pk) {
        Buffer buffer = Buffer.buffer();
        buffer.appendString("-----BEGIN PRIVATE KEY-----\n");
        buffer.appendString(Base64.getEncoder().encodeToString(pk.getEncoded()));
        buffer.appendString("\n-----END PRIVATE KEY-----\n\n");

        return buffer;
    }
}
