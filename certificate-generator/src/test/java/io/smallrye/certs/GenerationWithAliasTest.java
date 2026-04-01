package io.smallrye.certs;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.nio.file.Path;
import java.util.Collection;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.vertx.core.Vertx;
import io.vertx.core.net.*;

public class GenerationWithAliasTest {

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
    void JKSGeneration(@TempDir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withFormat(Format.JKS)
                .withPassword("password")
                .withAlias("alias", new AliasRequest().withCN("localhost").withPassword("alias-secret"));
        new CertificateGenerator(tempDir, true).generate(request);

        KeyCertOptions serverOptions = new JksOptions()
                .setPath(new File(tempDir.toFile(), "test-keystore.jks").getAbsolutePath()).setAlias("alias")
                .setAliasPassword("alias-secret").setPassword("password");
        TrustOptions clientOptions = new JksOptions()
                .setPath(new File(tempDir.toFile(), "test-truststore.jks").getAbsolutePath()).setAlias("alias")
                .setAliasPassword("alias-secret").setPassword("password");
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void PEMGeneration(@TempDir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withFormat(Format.PEM)
                .withAlias("alias", new AliasRequest().withCN("localhost"));
        Collection<CertificateFiles> files = new CertificateGenerator(tempDir, true).generate(request);
        Assertions.assertThat(files).hasSize(2);
        assertThat(files.stream().findFirst().get()).isInstanceOf(PemCertificateFiles.class);

        KeyCertOptions serverOptions = new PemKeyCertOptions()
                .addKeyPath(new File(tempDir.toFile(), "alias.key").getAbsolutePath())
                .addCertPath(new File(tempDir.toFile(), "alias.crt").getAbsolutePath());
        TrustOptions clientOptions = new PemTrustOptions()
                .addCertPath(new File(tempDir.toFile(), "alias-ca.crt").getAbsolutePath());
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void PCKS12Generation(@TempDir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withFormat(Format.PKCS12)
                .withAlias("alias", new AliasRequest().withCN("localhost").withPassword("alias-secret"))
                .withPassword("secret");
        Collection<CertificateFiles> files = new CertificateGenerator(tempDir, true).generate(request);
        Assertions.assertThat(files).hasSize(1);
        assertThat(files.stream().findFirst().get()).isInstanceOf(Pkcs12CertificateFiles.class);

        KeyCertOptions serverOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), "test-keystore.p12").getAbsolutePath()).setPassword("secret")
                .setAlias("alias").setAliasPassword("alias-secret");
        TrustOptions clientOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), "test-truststore.p12").getAbsolutePath()).setPassword("secret")
                .setAlias("alias").setAliasPassword("alias-secret");
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSWithJKSGeneration(@TempDir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withClientCertificate()
                .withFormat(Format.JKS)
                .withAlias("alias",
                        new AliasRequest().withCN("localhost").withPassword("alias-secret").withClientCertificate());
        new CertificateGenerator(tempDir, true).generate(request);

        KeyCertOptions serverOptions = new JksOptions()
                .setPath(new File(tempDir.toFile(), "test-keystore.jks").getAbsolutePath()).setPassword("secret")
                .setAlias("alias").setAliasPassword("alias-secret");
        TrustOptions serverTrustOptions = new JksOptions()
                .setPath(new File(tempDir.toFile(), "test-server-truststore.jks").getAbsolutePath()).setPassword("secret")
                .setAlias("alias").setAliasPassword("alias-secret");

        KeyCertOptions clientOptions = new JksOptions()
                .setPath(new File(tempDir.toFile(), "test-client-keystore.jks").getAbsolutePath()).setPassword("secret")
                .setAlias("alias").setAliasPassword("alias-secret");
        TrustOptions clientTrustOptions = new JksOptions()
                .setPath(new File(tempDir.toFile(), "test-client-truststore.jks").getAbsolutePath()).setPassword("secret")
                .setAlias("alias").setAliasPassword("alias-secret");

        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverOptions, serverTrustOptions);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientOptions,
                clientTrustOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSWithP12Generation(@TempDir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withClientCertificate()
                .withFormat(Format.PKCS12)
                .withAlias("alias",
                        new AliasRequest().withCN("localhost").withPassword("alias-secret").withClientCertificate());
        new CertificateGenerator(tempDir, true).generate(request);

        KeyCertOptions serverOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), "test-keystore.p12").getAbsolutePath()).setPassword("secret")
                .setAlias("alias").setAliasPassword("alias-secret");
        TrustOptions serverTrustOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), "test-server-truststore.p12").getAbsolutePath()).setPassword("secret")
                .setAlias("alias").setAliasPassword("alias-secret");

        KeyCertOptions clientOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), "test-client-keystore.p12").getAbsolutePath()).setPassword("secret")
                .setAlias("alias").setAliasPassword("alias-secret");
        TrustOptions clientTrustOptions = new PfxOptions()
                .setPath(new File(tempDir.toFile(), "test-client-truststore.p12").getAbsolutePath()).setPassword("secret")
                .setAlias("alias").setAliasPassword("alias-secret");

        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverOptions, serverTrustOptions);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientOptions,
                clientTrustOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSWithPemGeneration(@TempDir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withFormat(Format.PEM)
                .withAlias("alias", new AliasRequest().withCN("localhost").withClientCertificate());
        new CertificateGenerator(tempDir, true).generate(request);

        KeyCertOptions serverOptions = new PemKeyCertOptions()
                .addCertPath(new File(tempDir.toFile(), "alias.crt").getAbsolutePath())
                .addKeyPath(new File(tempDir.toFile(), "alias.key").getAbsolutePath());
        TrustOptions serverTrustOptions = new PemTrustOptions()
                .addCertPath(new File(tempDir.toFile(), "alias-server-ca.crt").getAbsolutePath());

        KeyCertOptions clientOptions = new PemKeyCertOptions()
                .addCertPath(new File(tempDir.toFile(), "alias-client.crt").getAbsolutePath())
                .addKeyPath(new File(tempDir.toFile(), "alias-client.key").getAbsolutePath());
        TrustOptions clientTrustOptions = new PemTrustOptions()
                .addCertPath(new File(tempDir.toFile(), "alias-client-ca.crt").getAbsolutePath());

        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverOptions, serverTrustOptions);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientOptions,
                clientTrustOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }
}
