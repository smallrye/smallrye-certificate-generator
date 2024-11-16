package io.smallrye.certs;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Collection;

import io.smallrye.certs.pem.parsers.EncryptedPKCS8Parser;
import io.vertx.core.buffer.Buffer;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.resource.Dir;

import io.vertx.core.Vertx;
import io.vertx.core.net.*;

public class GenerationTest {

    private static Vertx vertx;

    @BeforeAll
    static void initVertx() {
        vertx = Vertx.vertx();
    }

    @AfterAll
    static void closeVertx() {
        vertx.close().toCompletionStage().toCompletableFuture().join();
    }

    @Test
    void JKSGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withFormat(Format.JKS)
                .withPassword("password");
        new CertificateGenerator(tempDir, true).generate(request);

        KeyCertOptions serverOptions = new JksOptions()
                .setPath(new File(tempDir.toFile(), "test-keystore.jks").getAbsolutePath()).setPassword("password");
        TrustOptions clientOptions = new JksOptions()
                .setPath(new File(tempDir.toFile(), "test-truststore.jks").getAbsolutePath()).setPassword("password");
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void PEMGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withFormat(Format.PEM);
        Collection<CertificateFiles> files = new CertificateGenerator(tempDir, true).generate(request);
        Assertions.assertThat(files).hasSize(1);
        assertThat(files.stream().findFirst().get()).isInstanceOf(PemCertificateFiles.class);

        KeyCertOptions serverOptions = new PemKeyCertOptions()
                .addKeyPath(new File(tempDir.toFile(), "test.key").getAbsolutePath())
                .addCertPath(new File(tempDir.toFile(), "test.crt").getAbsolutePath());
        TrustOptions clientOptions = new PemTrustOptions()
                .addCertPath(new File(tempDir.toFile(), "test-ca.crt").getAbsolutePath());
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void PEMGenerationWithEncryptedPrivateKey(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withFormat(Format.ENCRYPTED_PEM)
                .withPassword("secret");
        Collection<CertificateFiles> files = new CertificateGenerator(tempDir, true).generate(request);
        Assertions.assertThat(files).hasSize(1);
        assertThat(files.stream().findFirst().get()).isInstanceOf(PemCertificateFiles.class);

        // We need to translate the PEM file.
        Buffer buffer = decrypt(new File(tempDir.toFile(), "test.key"), "secret");

        KeyCertOptions serverOptions = new PemKeyCertOptions()
                .addKeyValue(buffer)
                .addCertPath(new File(tempDir.toFile(), "test.crt").getAbsolutePath());
        TrustOptions clientOptions = new PemTrustOptions()
                .addCertPath(new File(tempDir.toFile(), "test-ca.crt").getAbsolutePath());
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    private static Buffer decrypt(File pem, String password) throws IOException {
        var content = Files.readString(pem.toPath());
        var parser = new EncryptedPKCS8Parser();
        return parser.decryptKey(content, password);
    }

    @Test
    void PCKS12Generation(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withFormat(Format.PKCS12)
                .withPassword("secret");
        Collection<CertificateFiles> files = new CertificateGenerator(tempDir, true).generate(request);
        Assertions.assertThat(files).hasSize(1);
        assertThat(files.stream().findFirst().get()).isInstanceOf(Pkcs12CertificateFiles.class);

        KeyCertOptions serverOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), "test-keystore.p12").getAbsolutePath()).setPassword("secret");
        TrustOptions clientOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), "test-truststore.p12").getAbsolutePath()).setPassword("secret");
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void multiFormatWithP12AndPemGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withFormat(Format.PKCS12)
                .withFormat(Format.PEM)
                .withPassword("password");
        Collection<CertificateFiles> files = new CertificateGenerator(tempDir, true).generate(request);
        Assertions.assertThat(files).hasSize(2);

        KeyCertOptions serverOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), "test-keystore.p12").getAbsolutePath()).setPassword("password");
        TrustOptions clientOptions = new PemTrustOptions()
                .addCertPath(new File(tempDir.toFile(), "test-ca.crt").getAbsolutePath());
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void multiFormatWithJKSAndPemGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withFormat(Format.JKS)
                .withFormat(Format.PEM)
                .withPassword("password");
        Collection<CertificateFiles> files = new CertificateGenerator(tempDir, true).generate(request);
        Assertions.assertThat(files).hasSize(2);

        KeyCertOptions serverOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), "test-keystore.jks").getAbsolutePath()).setPassword("password");
        TrustOptions clientOptions = new PemTrustOptions()
                .addCertPath(new File(tempDir.toFile(), "test-ca.crt").getAbsolutePath());
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSWithPemGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withClientCertificate()
                .withFormat(Format.PEM);
        Collection<CertificateFiles> files = new CertificateGenerator(tempDir, true).generate(request);
        Assertions.assertThat(files).hasSize(1);
        assertThat(files.stream().findFirst().get()).isInstanceOf(PemCertificateFiles.class);

        KeyCertOptions serverOptions = new PemKeyCertOptions()
                .addKeyPath(new File(tempDir.toFile(), "test.key").getAbsolutePath())
                .addCertPath(new File(tempDir.toFile(), "test.crt").getAbsolutePath());
        PemTrustOptions serverTrustOptions = new PemTrustOptions()
                .addCertPath(new File(tempDir.toFile(), "test-server-ca.crt").getAbsolutePath());

        KeyCertOptions clientOptions = new PemKeyCertOptions()
                .addKeyPath(new File(tempDir.toFile(), "test-client.key").getAbsolutePath())
                .addCertPath(new File(tempDir.toFile(), "test-client.crt").getAbsolutePath());
        TrustOptions clientTrustOptions = new PemTrustOptions()
                .addCertPath(new File(tempDir.toFile(), "test-client-ca.crt").getAbsolutePath());
        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverOptions, serverTrustOptions);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientOptions,
                clientTrustOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSWithJKSGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withClientCertificate()
                .withFormat(Format.JKS);
        new CertificateGenerator(tempDir, true).generate(request);

        KeyCertOptions serverOptions = new JksOptions()
                .setPath(new File(tempDir.toFile(), "test-keystore.jks").getAbsolutePath()).setPassword("secret")
                .setAlias("test");
        TrustOptions serverTrustOptions = new JksOptions()
                .setPath(new File(tempDir.toFile(), "test-server-truststore.jks").getAbsolutePath()).setPassword("secret")
                .setAlias("test");

        KeyCertOptions clientOptions = new JksOptions()
                .setPath(new File(tempDir.toFile(), "test-client-keystore.jks").getAbsolutePath()).setPassword("secret")
                .setAlias("test");
        TrustOptions clientTrustOptions = new JksOptions()
                .setPath(new File(tempDir.toFile(), "test-client-truststore.jks").getAbsolutePath()).setPassword("secret")
                .setAlias("test");

        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverOptions, serverTrustOptions);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientOptions,
                clientTrustOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSWithPKCS12Generation(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withClientCertificate()
                .withFormat(Format.PKCS12);
        new CertificateGenerator(tempDir, true).generate(request);

        KeyCertOptions serverOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), "test-keystore.p12").getAbsolutePath()).setPassword("secret")
                .setAlias("test");
        TrustOptions serverTrustOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), "test-server-truststore.p12").getAbsolutePath()).setPassword("secret")
                .setAlias("test");

        KeyCertOptions clientOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), "test-client-keystore.p12").getAbsolutePath()).setPassword("secret")
                .setAlias("test");
        TrustOptions clientTrustOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), "test-client-truststore.p12").getAbsolutePath()).setPassword("secret")
                .setAlias("test");

        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverOptions, serverTrustOptions);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientOptions,
                clientTrustOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSWithJKSAndEncryptedPemGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withClientCertificate()
                .withFormat(Format.JKS)
                .withFormat(Format.ENCRYPTED_PEM);
        new CertificateGenerator(tempDir, true).generate(request);

        File serverKeyStore = new File(tempDir.toFile(), "test-keystore.jks");
        assertThat(serverKeyStore).isFile();
        KeyCertOptions serverOptions = new JksOptions().setPath(serverKeyStore.getAbsolutePath()).setPassword("secret")
                .setAlias("test");
        File serverTrustStore = new File(tempDir.toFile(), "test-server-truststore.jks");
        assertThat(serverTrustStore).isFile();
        TrustOptions serverTrustOptions = new JksOptions().setPath(serverTrustStore.getAbsolutePath()).setPassword("secret")
                .setAlias("test");

        File clientKey = new File(tempDir.toFile(), "test-client.key");
        assertThat(clientKey).isFile();
        File clientCert = new File(tempDir.toFile(), "test-client.crt");
        assertThat(clientCert).isFile();

        Buffer buffer = decrypt(new File(tempDir.toFile(), "test-client.key"), "secret");

        KeyCertOptions clientOptions = new PemKeyCertOptions()
                .addKeyValue(buffer)
                .addCertPath(clientCert.getAbsolutePath());
        File clientTrustStore = new File(tempDir.toFile(), "test-client-ca.crt");
        assertThat(clientTrustStore).isFile();
        TrustOptions clientTrustOptions = new PemTrustOptions().addCertPath(clientTrustStore.getAbsolutePath());

        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverOptions, serverTrustOptions);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientOptions,
                clientTrustOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSWithJKSAndPemGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withClientCertificate()
                .withFormat(Format.JKS)
                .withFormat(Format.PEM);
        new CertificateGenerator(tempDir, true).generate(request);

        File serverKeyStore = new File(tempDir.toFile(), "test-keystore.jks");
        assertThat(serverKeyStore).isFile();
        KeyCertOptions serverOptions = new JksOptions().setPath(serverKeyStore.getAbsolutePath()).setPassword("secret")
                .setAlias("test");
        File serverTrustStore = new File(tempDir.toFile(), "test-server-truststore.jks");
        assertThat(serverTrustStore).isFile();
        TrustOptions serverTrustOptions = new JksOptions().setPath(serverTrustStore.getAbsolutePath()).setPassword("secret")
                .setAlias("test");

        File clientKey = new File(tempDir.toFile(), "test-client.key");
        assertThat(clientKey).isFile();
        File clientCert = new File(tempDir.toFile(), "test-client.crt");
        assertThat(clientCert).isFile();

        KeyCertOptions clientOptions = new PemKeyCertOptions()
                .addKeyPath(clientKey.getAbsolutePath())
                .addCertPath(clientCert.getAbsolutePath());
        File clientTrustStore = new File(tempDir.toFile(), "test-client-ca.crt");
        assertThat(clientTrustStore).isFile();
        TrustOptions clientTrustOptions = new PemTrustOptions().addCertPath(clientTrustStore.getAbsolutePath());

        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverOptions, serverTrustOptions);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientOptions,
                clientTrustOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSWithP12AndEncryptedPemGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withClientCertificate()
                .withFormat(Format.PKCS12)
                .withFormat(Format.ENCRYPTED_PEM);
        new CertificateGenerator(tempDir, true).generate(request);

        File serverKeyStore = new File(tempDir.toFile(), "test-keystore.p12");
        assertThat(serverKeyStore).isFile();
        KeyCertOptions serverOptions = new PfxOptions().setPath(serverKeyStore.getAbsolutePath()).setPassword("secret")
                .setAlias("test");
        File serverTrustStore = new File(tempDir.toFile(), "test-server-truststore.p12");
        assertThat(serverTrustStore).isFile();
        TrustOptions serverTrustOptions = new PfxOptions().setPath(serverTrustStore.getAbsolutePath()).setPassword("secret")
                .setAlias("test");

        File clientKey = new File(tempDir.toFile(), "test-client.key");
        assertThat(clientKey).isFile();
        File clientCert = new File(tempDir.toFile(), "test-client.crt");
        assertThat(clientCert).isFile();

        Buffer buffer = decrypt(new File(tempDir.toFile(), "test-client.key"), "secret");

        KeyCertOptions clientOptions = new PemKeyCertOptions()
                .addKeyValue(buffer)
                .addCertPath(clientCert.getAbsolutePath());
        File clientTrustStore = new File(tempDir.toFile(), "test-client-ca.crt");
        assertThat(clientTrustStore).isFile();
        TrustOptions clientTrustOptions = new PemTrustOptions().addCertPath(clientTrustStore.getAbsolutePath());

        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverOptions, serverTrustOptions);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientOptions,
                clientTrustOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSWithP12AndPemGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withClientCertificate()
                .withFormat(Format.PKCS12)
                .withFormat(Format.PEM);
        new CertificateGenerator(tempDir, true).generate(request);

        File serverKeyStore = new File(tempDir.toFile(), "test-keystore.p12");
        assertThat(serverKeyStore).isFile();
        KeyCertOptions serverOptions = new PfxOptions().setPath(serverKeyStore.getAbsolutePath()).setPassword("secret")
                .setAlias("test");
        File serverTrustStore = new File(tempDir.toFile(), "test-server-truststore.p12");
        assertThat(serverTrustStore).isFile();
        TrustOptions serverTrustOptions = new PfxOptions().setPath(serverTrustStore.getAbsolutePath()).setPassword("secret")
                .setAlias("test");

        File clientKey = new File(tempDir.toFile(), "test-client.key");
        assertThat(clientKey).isFile();
        File clientCert = new File(tempDir.toFile(), "test-client.crt");
        assertThat(clientCert).isFile();

        KeyCertOptions clientOptions = new PemKeyCertOptions()
                .addKeyPath(clientKey.getAbsolutePath())
                .addCertPath(clientCert.getAbsolutePath());
        File clientTrustStore = new File(tempDir.toFile(), "test-client-ca.crt");
        assertThat(clientTrustStore).isFile();
        TrustOptions clientTrustOptions = new PemTrustOptions().addCertPath(clientTrustStore.getAbsolutePath());

        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverOptions, serverTrustOptions);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientOptions,
                clientTrustOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSWithP12AndJKSGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withClientCertificate()
                .withFormat(Format.PKCS12)
                .withFormat(Format.JKS);
        new CertificateGenerator(tempDir, true).generate(request);

        File serverKeyStore = new File(tempDir.toFile(), "test-keystore.p12");
        assertThat(serverKeyStore).isFile();
        KeyCertOptions serverOptions = new PfxOptions().setPath(serverKeyStore.getAbsolutePath()).setPassword("secret")
                .setAlias("test");
        File serverTrustStore = new File(tempDir.toFile(), "test-server-truststore.p12");
        assertThat(serverTrustStore).isFile();
        TrustOptions serverTrustOptions = new PfxOptions().setPath(serverTrustStore.getAbsolutePath()).setPassword("secret")
                .setAlias("test");

        File clientKey = new File(tempDir.toFile(), "test-client-keystore.jks");
        assertThat(clientKey).isFile();
        File clientCert = new File(tempDir.toFile(), "test-client-truststore.jks");
        assertThat(clientCert).isFile();
        JksOptions clientOptions = new JksOptions().setPath(clientKey.getAbsolutePath()).setPassword("secret").setAlias("test");
        JksOptions clientTrustOptions = new JksOptions().setPath(clientCert.getAbsolutePath()).setPassword("secret")
                .setAlias("test");

        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverOptions, serverTrustOptions);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientOptions,
                clientTrustOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSMultiFormatVerification(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withClientCertificate()
                .withFormat(Format.PKCS12)
                .withFormat(Format.JKS)
                .withFormat(Format.PEM);

        new CertificateGenerator(tempDir, true).generate(request);

        KeyStore p12ServerKeyStore = KeyStore.getInstance("PKCS12");
        p12ServerKeyStore.load(new FileInputStream(new File(tempDir.toFile(), "test-keystore.p12")), "secret".toCharArray());

        KeyStore p12ServerTruststore = KeyStore.getInstance("PKCS12");
        p12ServerTruststore.load(new FileInputStream(new File(tempDir.toFile(), "test-server-truststore.p12")),
                "secret".toCharArray());

        KeyStore p12ClientKeyStore = KeyStore.getInstance("PKCS12");
        p12ClientKeyStore.load(new FileInputStream(new File(tempDir.toFile(), "test-client-keystore.p12")),
                "secret".toCharArray());

        KeyStore p12ClientTrustStore = KeyStore.getInstance("PKCS12");
        p12ClientTrustStore.load(new FileInputStream(new File(tempDir.toFile(), "test-client-truststore.p12")),
                "secret".toCharArray());

        KeyStore jksServerKeyStore = KeyStore.getInstance("JKS");
        jksServerKeyStore.load(new FileInputStream(new File(tempDir.toFile(), "test-keystore.jks")), "secret".toCharArray());

        KeyStore jksServerTruststore = KeyStore.getInstance("JKS");
        jksServerTruststore.load(new FileInputStream(new File(tempDir.toFile(), "test-server-truststore.jks")),
                "secret".toCharArray());

        KeyStore jksClientKeyStore = KeyStore.getInstance("JKS");
        jksClientKeyStore.load(new FileInputStream(new File(tempDir.toFile(), "test-client-keystore.jks")),
                "secret".toCharArray());

        KeyStore jksClientTrustStore = KeyStore.getInstance("JKS");
        jksClientTrustStore.load(new FileInputStream(new File(tempDir.toFile(), "test-client-truststore.jks")),
                "secret".toCharArray());

        // JKS client cert should be verified using the P12 server truststore
        jksClientKeyStore.getCertificate("test").verify(p12ServerTruststore.getCertificate("test").getPublicKey());
        // P12 client cert should be verified using the JKS server truststore
        p12ClientKeyStore.getCertificate("test").verify(jksServerTruststore.getCertificate("test").getPublicKey());

        var clientCrt = CertificateUtils.loadCertificate(new File(tempDir.toFile(), "test-client.crt"));
        var serverCrt = CertificateUtils.loadCertificate(new File(tempDir.toFile(), "test.crt"));
        var clientCA = CertificateUtils.loadCertificate(new File(tempDir.toFile(), "test-client-ca.crt"));
        var serverCA = CertificateUtils.loadCertificate(new File(tempDir.toFile(), "test-server-ca.crt"));

        // PEM only verification
        clientCrt.verify(serverCA.getPublicKey());
        serverCrt.verify(clientCA.getPublicKey());

        serverCrt.verify(p12ClientTrustStore.getCertificate("test").getPublicKey());
        clientCA.verify(p12ServerKeyStore.getCertificate("test").getPublicKey());

        clientCrt.verify(p12ServerTruststore.getCertificate("test").getPublicKey());
        serverCA.verify(p12ClientKeyStore.getCertificate("test").getPublicKey());
    }

}
