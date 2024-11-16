package io.smallrye.certs;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class CertificateRequest {
    private String name;
    private String password;
    private List<Format> formats = new ArrayList<>();
    private Duration duration = Duration.ofDays(2);
    private String cn = "localhost";

    private boolean client = false;

    private final Map<String, AliasRequest> aliases = new HashMap<>();
    private final List<String> sans = new ArrayList<>();

    private boolean signed;
    private Issuer issuer;

    public CertificateRequest withName(String name) {
        this.name = name;
        return this;
    }

    public CertificateRequest withPassword(String password) {
        this.password = password;
        return this;
    }

    public CertificateRequest withFormats(List<Format> formats) {
        this.formats = formats;
        return this;
    }

    public CertificateRequest withFormat(Format format) {
        if (format.equals(Format.PEM)) {
            if (formats.contains(Format.ENCRYPTED_PEM)) {
                throw new IllegalArgumentException("Cannot mix PEM and ENCRYPTED_PEM formats");
            }
        }
        if (format.equals(Format.ENCRYPTED_PEM)) {
            if (formats.contains(Format.PEM)) {
                throw new IllegalArgumentException("Cannot mix PEM and ENCRYPTED_PEM formats");
            }
        }
        this.formats.add(format);
        return this;
    }

    public CertificateRequest withDuration(Duration duration) {
        this.duration = duration;
        return this;
    }

    public CertificateRequest withCN(String cn) {
        this.cn = cn;
        return this;
    }

    public CertificateRequest withClientCertificate() {
        this.client = true;
        return this;
    }

    public CertificateRequest withClientCertificate(boolean client) {
        this.client = client;
        return this;
    }

    public CertificateRequest withSubjectAlternativeName(String name) {
        this.sans.add(name);
        return this;
    }

    public CertificateRequest withAlias(String alias, AliasRequest request) {
        if (alias.equals(name)) {
            throw new IllegalArgumentException("The alias cannot be the same as the name of the main certificate");
        }
        this.aliases.put(alias, request);
        return this;
    }

    public record Issuer(X509Certificate issuer, PrivateKey issuerPrivateKey) {
    }

    public CertificateRequest signedWith(X509Certificate issuer, PrivateKey issuerPrivateKey) {
        this.signed = true;
        this.issuer = new Issuer(issuer, issuerPrivateKey);
        return this;
    }

    void validate() {
        if (cn == null || cn.isEmpty()) {
            cn = "localhost";
        }
    }

    public String getCN() {
        return cn;
    }

    public Duration getDuration() {
        return duration;
    }

    public String name() {
        return name;
    }

    public String getPassword() {
        return password;
    }

    public List<Format> formats() {
        return formats;
    }

    public boolean hasClient() {
        return client;
    }

    public List<String> getSubjectAlternativeNames() {
        return sans;
    }

    public Map<String, AliasRequest> aliases() {
        return aliases;
    }

    public boolean isSelfSigned() {
        return !signed;
    }

    public Issuer issuer() {
        return issuer;
    }
}
