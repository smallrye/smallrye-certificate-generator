package io.smallrye.certs;

import io.smallrye.certs.pem.parsers.EncryptedPKCS8Parser;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.net.JksOptions;
import io.vertx.core.net.KeyCertOptions;
import io.vertx.core.net.PemKeyCertOptions;
import io.vertx.core.net.PemTrustOptions;
import io.vertx.core.net.TrustOptions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

public class MixedFormatMTLSTest {

    private static Vertx vertx;

    @BeforeAll
    static void initVertx() {
        vertx = Vertx.vertx();
    }

    @AfterAll
    static void closeVertx() {
        vertx.close().toCompletionStage().toCompletableFuture().join();
    }

    private static Stream<Arguments> testMixingKeystoreAndTruststoreFormat() {
        // Server: Keystore formats, Truststore formats, Client: Keystore formats, Truststore formats

        List<Arguments> list = new ArrayList<>();
        List<Format> formats = List.of(Format.JKS, Format.PKCS12, Format.PEM);
        formats.forEach(serverKeystoreFormat -> formats.forEach(serverTruststoreFormat -> formats
                .forEach(clientKeystoreFormat -> formats.forEach(clientTruststoreFormat -> list.add(Arguments
                        .of(serverKeystoreFormat, serverTruststoreFormat, clientKeystoreFormat, clientTruststoreFormat))))));

        return list.stream();
    }

    private static Buffer decrypt(File pem, String password) throws IOException {
        var content = Files.readString(pem.toPath());
        var parser = new EncryptedPKCS8Parser();
        return parser.decryptKey(content, password);
    }

    @ParameterizedTest
    @MethodSource
    public void testMixingKeystoreAndTruststoreFormat(Format serverKeystoreFormat, Format serverTruststoreFormat,
            Format clientKeystoreFormat, Format clientTrustoreFormat) throws Exception {
        generate();

        KeyCertOptions serverKS = switch (serverKeystoreFormat) {
            case PEM -> new PemKeyCertOptions()
                    .addKeyPath("target/certs/test-mixed-mtls.key")
                    .addCertPath("target/certs/test-mixed-mtls.crt");
            case ENCRYPTED_PEM -> {
                Buffer buffer = decrypt(new File("target/certs/test-mixed-mtls.key"), "password");
                yield new PemKeyCertOptions()
                        .addKeyValue(buffer)
                        .addCertPath("target/certs/test-mixed-mtls.crt");
            }
            case JKS -> new JksOptions()
                    .setPath("target/certs/test-mixed-mtls-keystore.jks")
                    .setPassword("password");
            case PKCS12 -> new JksOptions()
                    .setPath("target/certs/test-mixed-mtls-keystore.p12")
                    .setPassword("password");
        };

        KeyCertOptions clientKS = switch (clientKeystoreFormat) {
            case PEM -> new PemKeyCertOptions()
                    .addKeyPath("target/certs/test-mixed-mtls-client.key")
                    .addCertPath("target/certs/test-mixed-mtls-client.crt");
            case ENCRYPTED_PEM -> {
                Buffer buffer = decrypt(new File("target/certs/test-mixed-mtls-client.key"), "password");
                yield new PemKeyCertOptions()
                        .addKeyValue(buffer)
                        .addCertPath("target/certs/test-mixed-mtls-client.crt");
            }
            case JKS -> new JksOptions()
                    .setPath("target/certs/test-mixed-mtls-client-keystore.jks")
                    .setPassword("password");
            case PKCS12 -> new JksOptions()
                    .setPath("target/certs/test-mixed-mtls-client-keystore.p12")
                    .setPassword("password");
        };

        TrustOptions serverTS = switch (serverTruststoreFormat) {
            case PEM, ENCRYPTED_PEM -> new PemTrustOptions()
                    .addCertPath("target/certs/test-mixed-mtls-server-ca.crt");
            case JKS -> new JksOptions()
                    .setPath("target/certs/test-mixed-mtls-server-truststore.jks")
                    .setPassword("password");
            case PKCS12 -> new JksOptions()
                    .setPath("target/certs/test-mixed-mtls-server-truststore.p12")
                    .setPassword("password");
        };

        TrustOptions clientTS = switch (clientTrustoreFormat) {
            case PEM, ENCRYPTED_PEM -> new PemTrustOptions()
                    .addCertPath("target/certs/test-mixed-mtls-client-ca.crt");
            case JKS -> new JksOptions()
                    .setPath("target/certs/test-mixed-mtls-client-truststore.jks")
                    .setPassword("password");
            case PKCS12 -> new JksOptions()
                    .setPath("target/certs/test-mixed-mtls-client-truststore.p12")
                    .setPassword("password");
        };

        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverKS, serverTS);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientKS, clientTS);
        assertThat(response.statusCode()).isEqualTo(200);

    }

    private void generate() throws Exception {
        File target = new File("target/certs");
        if (!target.isDirectory()) {
            target.mkdirs();
        }
        CertificateRequest request = new CertificateRequest()
                .withName("test-mixed-mtls")
                .withFormats(List.of(Format.JKS, Format.PKCS12, Format.PEM))
                .withClientCertificate()
                .withPassword("password");
        CertificateGenerator generator = new CertificateGenerator(new File("target/certs").toPath(), true);
        generator.generate(request);
    }

}
