package io.smallrye.certs;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import io.vertx.core.Vertx;
import io.vertx.core.net.PemKeyCertOptions;
import io.vertx.core.net.PemTrustOptions;
import io.vertx.core.net.PfxOptions;

class GenerationWithKeyAlgorithmTest {

    private static final String PASSWORD = "password";

    private static Vertx vertx;

    @BeforeAll
    static void initVertx() {
        vertx = Vertx.vertx();
    }

    @AfterAll
    static void closeVertx() {
        if (vertx != null) {
            vertx.close().toCompletionStage().toCompletableFuture().join();
        }
    }

    @Test
    void testDefaultIsRsa(@TempDir Path tempDir) throws Exception {
        Collection<CertificateFiles> files = generatePkcs12(tempDir, "default-alg", null);
        assertThat(files).hasSize(1);
        assertThat(files.stream().findFirst().get()).isInstanceOf(Pkcs12CertificateFiles.class);

        assertKeyAlgorithm(tempDir, "default-alg", "RSA");
        verifyPkcs12TlsHandshake(tempDir, "default-alg");
    }

    static Stream<Arguments> ecAlgorithms() {
        return Stream.of(
                Arguments.of(KeyAlgorithm.EC_P256, "EC"),
                Arguments.of(KeyAlgorithm.EC_P384, "EC"));
    }

    @ParameterizedTest
    @MethodSource("ecAlgorithms")
    void testEcGeneration(KeyAlgorithm keyAlgorithm, String expectedAlgorithm, @TempDir Path tempDir) throws Exception {
        Collection<CertificateFiles> files = generatePkcs12(tempDir, "ec-test", keyAlgorithm);
        assertThat(files).hasSize(1);
        assertThat(files.stream().findFirst().get()).isInstanceOf(Pkcs12CertificateFiles.class);

        assertKeyAlgorithm(tempDir, "ec-test", expectedAlgorithm);
        verifyPkcs12TlsHandshake(tempDir, "ec-test");
    }

    @Test
    void testEcP256Tls(@TempDir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("ec-tls")
                .withFormat(Format.PEM)
                .withKeyAlgorithm(KeyAlgorithm.EC_P256);
        Collection<CertificateFiles> files = new CertificateGenerator(tempDir, true).generate(request);
        assertThat(files).hasSize(1);
        assertThat(files.stream().findFirst().get()).isInstanceOf(PemCertificateFiles.class);

        X509Certificate cert = CertificateUtils.loadCertificate(new File(tempDir.toFile(), "ec-tls.crt"));
        assertThat(cert.getPublicKey().getAlgorithm()).isEqualTo("EC");

        var serverOptions = new PemKeyCertOptions()
                .addKeyPath(new File(tempDir.toFile(), "ec-tls.key").getAbsolutePath())
                .addCertPath(new File(tempDir.toFile(), "ec-tls.crt").getAbsolutePath());
        var clientOptions = new PemTrustOptions()
                .addCertPath(new File(tempDir.toFile(), "ec-tls-ca.crt").getAbsolutePath());
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);
        assertThat(response.statusCode()).isEqualTo(200);
    }

    private static Collection<CertificateFiles> generatePkcs12(Path tempDir, String name, KeyAlgorithm keyAlgorithm)
            throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName(name)
                .withFormat(Format.PKCS12)
                .withPassword(PASSWORD);
        if (keyAlgorithm != null) {
            request.withKeyAlgorithm(keyAlgorithm);
        }
        return new CertificateGenerator(tempDir, true).generate(request);
    }

    private static void assertKeyAlgorithm(Path tempDir, String name, String expectedAlgorithm) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream(new File(tempDir.toFile(), name + "-keystore.p12")), PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate(name);
        assertThat(cert.getPublicKey().getAlgorithm()).isEqualTo(expectedAlgorithm);
    }

    private void verifyPkcs12TlsHandshake(Path tempDir, String name) throws Exception {
        var serverOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), name + "-keystore.p12").getAbsolutePath())
                .setPassword(PASSWORD);
        var clientOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), name + "-truststore.p12").getAbsolutePath())
                .setPassword(PASSWORD);
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);
        assertThat(response.statusCode()).isEqualTo(200);
    }
}
