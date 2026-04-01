package io.smallrye.certs;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.nio.file.Path;
import java.security.KeyStore;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class GeneratedKeyStoreTest {

    @Test
    void verifyIfJKSKeyStoreSupportAliasPassword(@TempDir Path dir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withFormat(Format.JKS)
                .withPassword("secret")
                .withName("jks-alias-verif")
                .withAlias("alias1", new AliasRequest().withPassword("password-alias1"))
                .withAlias("alias2", new AliasRequest().withPassword("password-alias2"));

        CertificateGenerator generator = new CertificateGenerator(dir, true);
        generator.generate(request);

        KeyStore ks = KeyStore.getInstance("JKS");
        File jks = new File(dir.toFile(), "jks-alias-verif-keystore.jks");
        try (var fis = new java.io.FileInputStream(jks)) {
            ks.load(fis, "secret".toCharArray());
        }

        assertThat(ks.containsAlias("jks-alias-verif")).isTrue();
        assertThat(ks.containsAlias("alias1")).isTrue();
        assertThat(ks.containsAlias("alias2")).isTrue();

        // Verify the certs
        assertThat(ks.getCertificate("jks-alias-verif")).isNotNull();
        assertThat(ks.getCertificate("alias1")).isNotNull();
        assertThat(ks.getCertificate("alias2")).isNotNull();

        // Verify the keys
        assertThat(ks.getKey("jks-alias-verif", "secret".toCharArray())).isNotNull();
        assertThat(ks.getKey("alias1", "password-alias1".toCharArray())).isNotNull();
        assertThat(ks.getKey("alias2", "password-alias2".toCharArray())).isNotNull();
    }

    @Test
    void verifyIfP12SKeyStoreSupportAliasPassword(@TempDir Path dir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withFormat(Format.PKCS12)
                .withPassword("secret")
                .withName("p12-alias-verif")
                .withAlias("alias1", new AliasRequest().withPassword("password-alias1"))
                .withAlias("alias2", new AliasRequest());

        CertificateGenerator generator = new CertificateGenerator(dir, true);
        generator.generate(request);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        File jks = new File(dir.toFile(), "p12-alias-verif-keystore.p12");
        try (var fis = new java.io.FileInputStream(jks)) {
            ks.load(fis, "secret".toCharArray());
        }

        assertThat(ks.containsAlias("p12-alias-verif")).isTrue();
        assertThat(ks.containsAlias("alias1")).isTrue();
        assertThat(ks.containsAlias("alias2")).isTrue();

        // Verify the certs
        assertThat(ks.getCertificate("p12-alias-verif")).isNotNull();
        assertThat(ks.getCertificate("alias1")).isNotNull();
        assertThat(ks.getCertificate("alias2")).isNotNull();

        // Verify the keys
        assertThat(ks.getKey("p12-alias-verif", "secret".toCharArray())).isNotNull();
        assertThat(ks.getKey("alias1", "password-alias1".toCharArray())).isNotNull();
        assertThat(ks.getKey("alias2", null)).isNotNull();

    }

}
