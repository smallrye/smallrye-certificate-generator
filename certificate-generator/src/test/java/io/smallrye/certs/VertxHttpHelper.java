package io.smallrye.certs;

import io.vertx.core.Vertx;
import io.vertx.core.http.*;
import io.vertx.core.net.*;

public class VertxHttpHelper {

    private VertxHttpHelper() {
        // Avoid direct instantiation
    }

    public static HttpServer createHttpServer(Vertx vertx, KeyCertOptions options) {
        return vertx.createHttpServer(new HttpServerOptions().setSsl(true).setKeyCertOptions(options))
                .requestHandler(req -> req.response().end("OK"))
                .listen(0)
                .await();
    }

    public static HttpClientResponse createHttpClientAndInvoke(Vertx vertx, HttpServer server, TrustOptions options) {
        return createHttpClientAndInvoke(vertx, server, options, true);
    }

    public static HttpClientResponse createHttpClientAndInvoke(Vertx vertx, HttpServer server, TrustOptions options,
            boolean verifyHost) {

        if (options == null) {
            return vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true).setDefaultHost("localhost").setDefaultPort(server.actualPort()).setVerifyHost(verifyHost))
                    .request(HttpMethod.GET, "/").flatMap(HttpClientRequest::send)
                    .await();
        }

        HttpClientAgent client = vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true).setDefaultHost("localhost").setDefaultPort(server.actualPort())
                .setTrustOptions(options)
                .setVerifyHost(verifyHost));

        HttpClientResponse response = client
                .request(HttpMethod.GET, "/").flatMap(HttpClientRequest::send)
                .await();

        client.close().await();
        return response;
    }

    public static HttpServer createHttpServerWithMutualAuth(Vertx vertx, KeyCertOptions serverOptions,
            TrustOptions trustOptions) {
        HttpServerOptions options = new HttpServerOptions()
                .setSsl(true)
                .setKeyCertOptions(serverOptions)
                .setTrustOptions(trustOptions)
                .setClientAuth(ClientAuth.REQUIRED);

        return vertx.createHttpServer(options)
                .requestHandler(req -> req.response().end("OK"))
                .listen(0)
                .await();
    }

    static HttpClientResponse createHttpClientWithMutualAuthAndInvoke(Vertx vertx, HttpServer server,
            KeyCertOptions clientOptions, TrustOptions trustOptions) {
        HttpClientOptions localhost = new HttpClientOptions()
                .setSsl(true).setDefaultHost("localhost").setDefaultPort(server.actualPort())
                .setTrustOptions(trustOptions)
                .setKeyCertOptions(clientOptions);
        HttpClientAgent client = vertx.createHttpClient(localhost);
        HttpClientResponse response = client
                .request(HttpMethod.GET, "/").flatMap(HttpClientRequest::send)
                .await();
        client.close().await();
        return response;
    }
}
