package io.smallrye.certs.junit5;

public @interface Alias {

    /**
     * Sets the name of the certificate.
     */
    String name();

    /**
     * Sets the password of the certificate alias if needed.
     */
    String password() default "";

    /**
     * Sets the CN (common name) of the certificate.
     */
    String cn() default "localhost";

    /**
     * Sets whether the certificate is a client certificate. This is useful for mutual TLS.
     */
    boolean client() default false;

    /**
     * Sets the subject alternative names of the certificate.
     * Must follow the format "DNS:example.com", "IP:127.0.0.1", or "URI:spiffe://example.org/service".
     */
    String[] subjectAlternativeNames() default {};

}
