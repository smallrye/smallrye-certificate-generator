package io.smallrye.certs;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

public enum KeyAlgorithm {

    RSA_2048("RSA", 2048, null, "SHA256WithRSAEncryption"),
    EC_P256("EC", 256, "secp256r1", "SHA256withECDSA"),
    EC_P384("EC", 384, "secp384r1", "SHA384withECDSA");

    private final String algorithm;
    private final int keySize;
    private final String ecCurve;
    private final String signatureAlgorithm;

    KeyAlgorithm(String algorithm, int keySize, String ecCurve, String signatureAlgorithm) {
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.ecCurve = ecCurve;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public String signatureAlgorithm() {
        return signatureAlgorithm;
    }

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        return generateKeyPair(KeyPairGenerator.getInstance(algorithm));
    }

    public KeyPair generateKeyPairWithBouncyCastleProvider()
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return generateKeyPair(KeyPairGenerator.getInstance(algorithm, "BC"));
    }

    private KeyPair generateKeyPair(KeyPairGenerator kpg) throws NoSuchAlgorithmException {
        try {
            if (ecCurve != null) {
                kpg.initialize(new ECGenParameterSpec(ecCurve), new SecureRandom());
            } else {
                kpg.initialize(keySize, new SecureRandom());
            }
        } catch (InvalidAlgorithmParameterException e) {
            throw new NoSuchAlgorithmException("Unsupported ecCurve: " + ecCurve, e);
        }
        return kpg.generateKeyPair();
    }
}
