package io.smallrye.certs.ca;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.smallrye.certs.CertificateGenerator;
import io.smallrye.certs.CertificateRequest;
import io.smallrye.certs.Format;

/**
 * Generate a CA certificate (without the installation) and generate a signed certificate.
 */
public class GenerateCaTest {

    @Test
    void test() throws Exception {
        File out = new File("target/ca");
        out.mkdirs();

        var ca = new File(out, "ca.crt");
        var key = new File(out, "ca.key");
        var store = new File(out, "ks.p12");
        CaGenerator generator = new CaGenerator(ca, key, store, "test");
        generator.generate("localhost", "Test", "Test Dev", "home", "world", "Cloud");

        assertThat(ca).exists();
        assertThat(key).exists();
        assertThat(store).exists();

        File trustStore = new File(out, "truststore.p12");
        generator.generateTrustStore(trustStore);
        assertThat(trustStore).exists();

        // Generate a signed certificate
        CertificateGenerator gen = new CertificateGenerator(out.toPath(), true);
        gen.generate(new CertificateRequest().withName("test").signedWith(loadRootCertificate(ca), loadPrivateKey(key))
                .withFormat(Format.PKCS12).withPassword("secret"));

        File signedKS = new File(out, "test-keystore.p12");
        File signedTS = new File(out, "test-truststore.p12");

        assertThat(signedKS).exists();
        assertThat(signedTS).exists();

        try (FileInputStream fis = new FileInputStream(signedKS)) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(fis, "secret".toCharArray());
            assertThat(ks.getCertificate("test")).isNotNull();
            assertThat(ks.getKey("test", "secret".toCharArray())).isNotNull();

            ks.getCertificate("test").verify(loadRootCertificate(ca).getPublicKey());
        }

        try (FileInputStream fis = new FileInputStream(signedTS)) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(fis, "secret".toCharArray());
            assertThat(ks.getCertificate("test")).isNotNull();
        }

    }

    /**
     * Reproducer for issue #92: {@code generate(...)} must not leak the keystore {@link FileInputStream}/output stream,
     * otherwise the file handle keeps the {@code .p12} locked on Windows and it cannot be deleted afterwards.
     */
    @Test
    void keystoreCanBeDeletedAfterGeneration(@TempDir File out) throws Exception {
        var ca = new File(out, "ca.crt");
        var key = new File(out, "ca.key");
        var store = new File(out, "ks.p12");
        CaGenerator generator = new CaGenerator(ca, key, store, "test");
        generator.generate("localhost", "Test", "Test Dev", "home", "world", "Cloud");

        assertThat(store).exists();

        // On Windows a leaked stream would keep the file locked and this deletion would throw.
        Files.delete(store.toPath());
        assertThat(store).doesNotExist();
    }

    private X509Certificate loadRootCertificate(File ca) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(ca)) {
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    private PrivateKey loadPrivateKey(File key) throws Exception {
        try (BufferedReader reader = new BufferedReader(new FileReader(key));
                PEMParser pemParser = new PEMParser(reader)) {
            Object obj = pemParser.readObject();
            if (obj instanceof KeyPair) {
                return ((KeyPair) obj).getPrivate();
            } else if (obj instanceof PrivateKeyInfo) {
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                return converter.getPrivateKey(((PrivateKeyInfo) obj));
            } else {
                throw new IllegalStateException(
                        "The file " + key.getAbsolutePath() + " does not contain a private key "
                                + obj.getClass().getName());
            }
        }
    }
}
