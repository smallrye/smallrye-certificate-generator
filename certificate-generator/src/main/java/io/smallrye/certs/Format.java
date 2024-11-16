package io.smallrye.certs;

/**
 * The format of certificates.
 */
public enum Format {
    PEM,
    ENCRYPTED_PEM,
    JKS,
    PKCS12;

    String extension() {
        return switch (this) {
            case PEM, ENCRYPTED_PEM -> "pem";
            case JKS -> "jks";
            case PKCS12 -> "p12";
        };
    }
}
