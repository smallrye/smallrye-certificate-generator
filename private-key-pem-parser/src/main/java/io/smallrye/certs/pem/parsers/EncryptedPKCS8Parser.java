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

    public EncryptedPKCS8Parser() {
    }

    /**
     * Extracts the private key from the encrypted PKCS#8 format.
     *
     * @param content the encrypted PKCS#8 content
     * @param password the password to decrypt the key
     * @return the private key or {@code null} if the content is not a PKCS#8 encrypted key
     */
    @Override
    public PrivateKey getKey(String content, String password) {
        try {
            Matcher matcher = PATTERN.matcher(content);
            if (matcher.find()) {
                var encoded = matcher.group(BASE64_TEXT_GROUP);
                var decoded = decodeBase64(encoded);
                return extract(decoded, password);
            }
        } catch (Exception e) {
            return null;
        }
        // Does not match PKCS8 encrypted pattern
        return null;
    }

    private PrivateKey extract(byte[] decoded, String password) {
        var key = decrypt(decoded, password);
        for (String algo : ALGORITHMS) {
            try {
                KeyFactory factory = KeyFactory.getInstance(algo);
                return factory.generatePrivate(key);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                // Ignore
            }
        }
        return null;
    }

    public static final String PBES2_ALGORITHM = "PBES2";

    static PKCS8EncodedKeySpec decrypt(byte[] bytes, String password) {
        try {
            EncryptedPrivateKeyInfo keyInfo = new EncryptedPrivateKeyInfo(bytes);
            AlgorithmParameters algorithmParameters = keyInfo.getAlgParameters();
            String encryptionAlgorithm = getEncryptionAlgorithm(algorithmParameters, keyInfo.getAlgName());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(encryptionAlgorithm);
            SecretKey key = keyFactory.generateSecret(new PBEKeySpec(password.toCharArray()));
            Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
            cipher.init(Cipher.DECRYPT_MODE, key, algorithmParameters);
            return keyInfo.getKeySpec(cipher);
        } catch (IOException | GeneralSecurityException ex) {
            throw new IllegalArgumentException("Error decrypting private key", ex);
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
     * @param secret the password to decrypt the key
     * @return the decrypted PKCS#8 key or {@code null} if the content is not a PKCS#8 encrypted key
     */
    public Buffer decryptKey(String content, String secret) {
        var pk = getKey(content, secret);
        if (pk == null) {
            return null;
        }
        Buffer buffer = Buffer.buffer();
        buffer.appendString("-----BEGIN PRIVATE KEY-----\n");
        buffer.appendString(Base64.getEncoder().encodeToString(pk.getEncoded()));
        buffer.appendString("\n-----END PRIVATE KEY-----\n\n");

        return buffer;
    }
}
