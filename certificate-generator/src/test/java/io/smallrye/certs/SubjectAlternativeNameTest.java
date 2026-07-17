package io.smallrye.certs;

import static org.assertj.core.api.Assertions.assertThat;
import static org.bouncycastle.asn1.x509.GeneralName.dNSName;
import static org.bouncycastle.asn1.x509.GeneralName.iPAddress;
import static org.bouncycastle.asn1.x509.GeneralName.uniformResourceIdentifier;

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

    @Test
    void testMixedSubjectAlternativeNames(@TempDir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("uri-test")
                .withFormat(Format.PKCS12)
                .withPassword("password")
                .withSubjectAlternativeName("URI:spiffe://example.org/my-service")
                .withSubjectAlternativeName("DNS:example.com")
                .withSubjectAlternativeName("IP:127.0.0.1");
        new CertificateGenerator(tempDir, true).generate(request);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(tempDir.resolve("uri-test-keystore.p12").toUri().toURL().openStream(), "password".toCharArray());

        X509Certificate cert = (X509Certificate) ks.getCertificate("uri-test");
        var sans = cert.getSubjectAlternativeNames();
        assertThat(sans).hasSize(3);

        assertThat(sans).anySatisfy(san -> {
            assertThat(san.get(0)).isEqualTo(uniformResourceIdentifier);
            assertThat(san.get(1)).isEqualTo("spiffe://example.org/my-service");
        });
        assertThat(sans).anySatisfy(san -> {
            assertThat(san.get(0)).isEqualTo(dNSName);
            assertThat(san.get(1)).isEqualTo("example.com");
        });
        assertThat(sans).anySatisfy(san -> {
            assertThat(san.get(0)).isEqualTo(iPAddress);
            assertThat(san.get(1)).isEqualTo("127.0.0.1");
        });
    }

    @Test
    void testUriOnlySubjectAlternativeName(@TempDir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("uri-only")
                .withFormat(Format.PKCS12)
                .withPassword("password")
                .withSubjectAlternativeName("URI:spiffe://example.org/my-service");
        new CertificateGenerator(tempDir, true).generate(request);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(tempDir.resolve("uri-only-keystore.p12").toUri().toURL().openStream(), "password".toCharArray());

        X509Certificate cert = (X509Certificate) ks.getCertificate("uri-only");
        var sans = cert.getSubjectAlternativeNames();
        assertThat(sans).hasSize(1);
        assertThat(sans).anySatisfy(san -> {
            assertThat(san.get(0)).isEqualTo(uniformResourceIdentifier);
            assertThat(san.get(1)).isEqualTo("spiffe://example.org/my-service");
        });
    }

}
