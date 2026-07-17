package io.smallrye.certs;

import java.util.ArrayList;
import java.util.List;

public class AliasRequest {
    private String password;
    private String cn;

    private final List<String> sans = new ArrayList<>();

    private boolean client = false;
    private KeyAlgorithm keyAlgorithm;

    public AliasRequest withPassword(String password) {
        this.password = password;
        return this;
    }

    public AliasRequest withCN(String cn) {
        this.cn = cn;
        return this;
    }

    public AliasRequest withKeyAlgorithm(KeyAlgorithm keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
        return this;
    }

    public AliasRequest withSubjectAlternativeName(String name) {
        this.sans.add(name);
        return this;
    }

    public AliasRequest withClientCertificate() {
        this.client = true;
        return this;
    }

    public AliasRequest withClientCertificate(boolean client) {
        this.client = client;
        return this;
    }

    public String getPassword() {
        return password;
    }

    public String getCN() {
        return cn;
    }

    public boolean hasClient() {
        return client;
    }

    public KeyAlgorithm getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public List<String> getSubjectAlternativeNames() {
        return sans;
    }
}
