package io.smallrye.certs;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class SubjectAlternativeNameTest {

    @Test
    void testSubjectAlternativeName(@TempDir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withFormat(Format.PKCS12)
                .withPassword("password")
                .withSubjectAlternativeName("IP:0.0.0.0")
                .withSubjectAlternativeName("DNS:example.com")
                .withSubjectAlternativeName("FOO:baz")
                .withAlias("alias", new AliasRequest().withCN("localhost").withPassword("alias-secret")
                        .withSubjectAlternativeName("IP:127.0.0.1")
                        .withSubjectAlternativeName("DNS:acme.org")
                        .withSubjectAlternativeName("FOO:bar"));
        new CertificateGenerator(tempDir, true).generate(request);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(tempDir.resolve("test-keystore.p12").toUri().toURL().openStream(), "password".toCharArray());

        // Verify main
        X509Certificate main = (X509Certificate) ks.getCertificate("test");
        assertThat(main.getSubjectAlternativeNames()).hasSize(3);

        // Verify alias
        X509Certificate alias = (X509Certificate) ks.getCertificate("alias");
        assertThat(alias.getSubjectAlternativeNames()).hasSize(3);
    }

}
