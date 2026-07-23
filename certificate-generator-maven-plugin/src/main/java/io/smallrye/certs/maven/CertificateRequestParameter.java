package io.smallrye.certs.maven;

import io.smallrye.certs.KeyAlgorithm;
import org.apache.maven.plugins.annotations.Parameter;

import java.util.List;

public class CertificateRequestParameter {

    @Parameter(required = true)
    private String name;
    @Parameter
    private String password;
    @Parameter(defaultValue = "localhost")
    private String cn;
    @Parameter(required = true)
    private List<String> formats;
    @Parameter(defaultValue = "2")
    private int duration;
    @Parameter(defaultValue = "false")
    private boolean client;

    @Parameter(defaultValue = "RSA_2048")
    private String keyAlgorithm;

    @Parameter
    private List<String> subjectAlternativeNames;

    @Parameter
    List<io.smallrye.certs.maven.AliasParameter> aliases;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getCn() {
        return cn;
    }

    public void setCn(String cn) {
        this.cn = cn;
    }

    public List<String> getFormats() {
        return formats;
    }

    public void setFormats(List<String> formats) {
        this.formats = formats;
    }

    public int getDuration() {
        return duration;
    }

    public void setDuration(int duration) {
        this.duration = duration;
    }

    public boolean isClient() {
        return client;
    }

    public void setClient(boolean client) {
        this.client = client;
    }

    public String getKeyAlgorithm() {
        if (keyAlgorithm == null) {
            return KeyAlgorithm.RSA_2048.name();
        }
        return keyAlgorithm;
    }

    public void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public void setSubjectAlternativeNames(List<String> subjectAlternativeNames) {
        this.subjectAlternativeNames = subjectAlternativeNames;
    }

    public List<String> getSubjectAlternativeNames() {
        return subjectAlternativeNames;
    }

    public List<io.smallrye.certs.maven.AliasParameter> getAliases() {
        return aliases;
    }

    public void setAliases(List<io.smallrye.certs.maven.AliasParameter> aliases) {
        this.aliases = aliases;
    }
}
