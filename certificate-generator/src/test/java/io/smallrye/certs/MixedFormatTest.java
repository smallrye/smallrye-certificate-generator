package io.smallrye.certs;

import io.smallrye.certs.pem.parsers.EncryptedPKCS8Parser;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpServer;
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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

public class MixedFormatTest {

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
        // Keystore format, Truststore format
        return Stream.of(
                Arguments.of(Format.JKS, Format.JKS),
                Arguments.of(Format.JKS, Format.PKCS12),
                Arguments.of(Format.JKS, Format.PEM),
                Arguments.of(Format.PKCS12, Format.PKCS12),
                Arguments.of(Format.PKCS12, Format.JKS),
                Arguments.of(Format.PKCS12, Format.PEM),
                Arguments.of(Format.PEM, Format.PEM),
                Arguments.of(Format.PEM, Format.JKS),
                Arguments.of(Format.PEM, Format.PKCS12),
                Arguments.of(Format.ENCRYPTED_PEM, Format.ENCRYPTED_PEM),
                Arguments.of(Format.ENCRYPTED_PEM, Format.JKS),
                Arguments.of(Format.ENCRYPTED_PEM, Format.PKCS12));
    }

    private static Buffer decrypt(File pem, String password) throws IOException {
        var content = Files.readString(pem.toPath());
        var parser = new EncryptedPKCS8Parser();
        return parser.decryptKey(content, password);
    }

    @ParameterizedTest
    @MethodSource
    public void testMixingKeystoreAndTruststoreFormat(Format keystoreFormat, Format truststoreFormat) throws Exception {
        generate(keystoreFormat, truststoreFormat);

        HttpServer server = switch (keystoreFormat) {
            case PEM -> {
                KeyCertOptions options = new PemKeyCertOptions()
                        .addKeyPath("target/certs/test-mixed.key")
                        .addCertPath("target/certs/test-mixed.crt");
                yield VertxHttpHelper.createHttpServer(vertx, options);
            }
            case ENCRYPTED_PEM -> {
                var buffer = decrypt(new File("target/certs/test-mixed.key"), "password");
                KeyCertOptions options = new PemKeyCertOptions()
                        .addKeyValue(buffer)
                        .addCertPath("target/certs/test-mixed.crt");
                yield VertxHttpHelper.createHttpServer(vertx, options);
            }
            case JKS -> {
                KeyCertOptions options = new JksOptions()
                        .setPath("target/certs/test-mixed-keystore.jks")
                        .setPassword("password");
                yield VertxHttpHelper.createHttpServer(vertx, options);
            }
            case PKCS12 -> {
                KeyCertOptions options = new JksOptions()
                        .setPath("target/certs/test-mixed-keystore.p12")
                        .setPassword("password");
                yield VertxHttpHelper.createHttpServer(vertx, options);
            }
        };

        TrustOptions trustOptions = switch (truststoreFormat) {
            case PEM, ENCRYPTED_PEM -> {
                PemTrustOptions options = new PemTrustOptions()
                        .addCertPath("target/certs/test-mixed-ca.crt");
                yield options;
            }
            case JKS -> {
                JksOptions options = new JksOptions()
                        .setPath("target/certs/test-mixed-truststore.jks")
                        .setPassword("password");
                yield options;
            }
            case PKCS12 -> {
                JksOptions options = new JksOptions()
                        .setPath("target/certs/test-mixed-truststore.p12")
                        .setPassword("password");
                yield options;
            }
        };

        HttpClientResponse response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, trustOptions);
        assertThat(response.statusCode()).isEqualTo(200);

    }

    private void generate(Format keystoreFormat, Format truststoreFormat) throws Exception {
        File target = new File("target/certs");
        if (!target.isDirectory()) {
            target.mkdirs();
        }
        Set<Format> formats = new HashSet<>();
        formats.add(keystoreFormat);
        formats.add(truststoreFormat);

        CertificateRequest request = new CertificateRequest()
                .withName("test-mixed")
                .withFormats(new ArrayList<>(formats))
                .withPassword("password");
        CertificateGenerator generator = new CertificateGenerator(new File("target/certs").toPath(), true);
        generator.generate(request);
    }

}
