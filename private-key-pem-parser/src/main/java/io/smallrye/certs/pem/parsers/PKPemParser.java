package io.smallrye.certs.pem.parsers;

import io.smallrye.certs.pem.der.ASN1ObjectIdentifier;

import java.security.PrivateKey;
import java.util.Base64;

public interface PKPemParser {

    String BASE64_TEXT = "([a-z0-9+/=\\r\\n]+)";
    int BASE64_TEXT_GROUP = 1;

    ASN1ObjectIdentifier RSA_ALGORITHM = ASN1ObjectIdentifier.OID_1_2_840_113549_1_1_1;

    PrivateKey getKey(String content, String secret);

    /**
     * Extracts the private key, and reports why when it cannot.
     *
     * @param content the PEM content
     * @param secret the secret to decrypt the key, if it is encrypted
     * @return the private key, never {@code null}
     * @throws IllegalArgumentException if the key cannot be extracted
     */
    default PrivateKey getKeyOrFail(String content, String secret) {
        PrivateKey key = getKey(content, secret);
        if (key == null) {
            throw new IllegalArgumentException("The content is not a private key that " + getClass().getSimpleName()
                    + " can read");
        }
        return key;
    }

    default byte[] decodeBase64(String content) {
        byte[] contentBytes = content.replaceAll("\r", "").replaceAll("\n", "").getBytes();
        return Base64.getDecoder().decode(contentBytes);
    }
}
