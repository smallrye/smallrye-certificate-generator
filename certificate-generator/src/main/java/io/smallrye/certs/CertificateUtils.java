package io.smallrye.certs;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class CertificateUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static X509Certificate generateCertificate(KeyPair keyPair, String cn, List<String> sans, Duration duration,
            CertificateRequest.Issuer issuerHolder) throws Exception {
        if (issuerHolder != null) {
            return generateSignedCertificate(keyPair, cn, sans, duration, issuerHolder);
        }
        var issuer = new X500Name("CN=" + cn);
        X509v3CertificateBuilder builder = getCertificateBuilder(keyPair, cn, sans, duration, issuer);
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(contentSignerBuilder.build(keyPair.getPrivate())));
    }

    private static X509v3CertificateBuilder getCertificateBuilder(KeyPair keyPair, String cn, List<String> sans,
            Duration duration, X500Name issuer) throws CertIOException, NoSuchAlgorithmException {
        var subject = new X500Name("CN=" + cn);
        var before = Instant.now().minus(2, ChronoUnit.DAYS);
        var after = Instant.now().plus(duration.toDays(), ChronoUnit.DAYS);
        var keyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(keyPair.getPublic().getEncoded()));
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.nanoTime()),
                new Date(before.toEpochMilli()),
                new Date(after.toEpochMilli()),
                subject,
                keyInfo);

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(keyPair.getPublic()));

        // Set certificate extensions
        // (1) digitalSignature extension
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment
                        | KeyUsage.keyAgreement | KeyUsage.nonRepudiation));

        builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

        // (2) extendedKeyUsage extension
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth }));

        // (3) subjectAlternativeName
        if (sans.isEmpty()) {
            DERSequence subjectAlternativeNames = new DERSequence(new ASN1Encodable[] {
                    new GeneralName(GeneralName.dNSName, cn),
                    new GeneralName(GeneralName.iPAddress, "127.0.0.1"),
                    new GeneralName(GeneralName.iPAddress, "0.0.0.0")
            });
            builder.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeNames);
        } else {
            DERSequence subjectAlternativeNames = new DERSequence(sans.stream().map(s -> {
                if (s.startsWith("DNS:")) {
                    return new GeneralName(GeneralName.dNSName, s.substring(4));
                } else if (s.startsWith("IP:")) {
                    return new GeneralName(GeneralName.iPAddress, s.substring(3));
                } else {
                    return new GeneralName(GeneralName.dNSName, s);
                }
            }).toArray(ASN1Encodable[]::new));
            builder.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeNames);
        }
        return builder;
    }

    public static X509Certificate generateSignedCertificate(KeyPair keyPair, String cn, List<String> sans, Duration duration,
            CertificateRequest.Issuer issuerHolder) throws Exception {
        var before = Instant.now().minus(2, ChronoUnit.DAYS);
        var after = Instant.now().plus(duration.toDays(), ChronoUnit.DAYS);
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSerialNumber(new java.math.BigInteger("2"));
        certGen.setIssuerDN(issuerHolder.issuer().getSubjectX500Principal());
        certGen.setSubjectDN(new X500Principal("CN=" + cn));
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setNotBefore(new Date(before.toEpochMilli())); // Yesterday
        certGen.setNotAfter(new Date(after.toEpochMilli())); // 1 year
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        if (sans.isEmpty()) {
            DERSequence subjectAlternativeNames = new DERSequence(new ASN1Encodable[] {
                    new GeneralName(GeneralName.dNSName, cn),
                    new GeneralName(GeneralName.iPAddress, "127.0.0.1"),
                    new GeneralName(GeneralName.iPAddress, "0.0.0.0")
            });
            certGen.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeNames);
        } else {
            DERSequence subjectAlternativeNames = new DERSequence(sans.stream().map(s -> {
                if (s.startsWith("DNS:")) {
                    return new GeneralName(GeneralName.dNSName, s.substring(4));
                } else if (s.startsWith("IP:")) {
                    return new GeneralName(GeneralName.iPAddress, s.substring(3));
                } else {
                    return new GeneralName(GeneralName.dNSName, s);
                }
            }).toArray(ASN1Encodable[]::new));
            certGen.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeNames);
        }
        certGen.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));
        // Do not add authority when using a CA-signed certificate

        // Set certificate extensions
        //        // (1) digitalSignature extension
        certGen.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment
                        | KeyUsage.keyAgreement | KeyUsage.nonRepudiation));

        certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

        // (2) extendedKeyUsage extension
        certGen.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth }));

        return certGen.generate(issuerHolder.issuerPrivateKey(), "BC");
    }

    public static void writeCertificateToPEM(X509Certificate certificate, File output, X509Certificate... chain)
            throws IOException, CertificateEncodingException {
        try (FileWriter fileWriter = new FileWriter(output);
                BufferedWriter pemWriter = new BufferedWriter(fileWriter)) {
            pemWriter.write("-----BEGIN CERTIFICATE-----\n");
            pemWriter.write(Base64.getEncoder().encodeToString(certificate.getEncoded()));
            pemWriter.write("\n-----END CERTIFICATE-----\n\n");
            for (X509Certificate cert : chain) {
                pemWriter.write("-----BEGIN CERTIFICATE-----\n");
                pemWriter.write(Base64.getEncoder().encodeToString(cert.getEncoded()));
                pemWriter.write("\n-----END CERTIFICATE-----\n\n");
            }
        }
    }

    // Define PBE parameters
    private static final String PBE_ALGORITHM = "PBEWithSHA1AndDESede";
    private static final int ITERATION_COUNT = 2048;
    private static final int SALT_SIZE = 8; // 8 bytes of salt

    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        return salt;
    }

    public static void writePrivateKeyToPem(PrivateKey privateKey, String password, File output) throws Exception {

        byte[] content = privateKey.getEncoded();

        if (password != null) {
            byte[] salt = generateSalt();
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
            SecretKey secretKey = keyFactory.generateSecret(pbeKeySpec);
            Cipher cipher = Cipher.getInstance(PBE_ALGORITHM);
            PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, ITERATION_COUNT);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParamSpec);

            // Encode the private key in PKCS#8 format
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
            byte[] encryptedKeyBytes = cipher.doFinal(pkcs8EncodedKeySpec.getEncoded());

            // Wrap encrypted data in EncryptedPrivateKeyInfo
            EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(cipher.getParameters(),
                    encryptedKeyBytes);
            content = encryptedPrivateKeyInfo.getEncoded();
        }

        try (FileWriter fileWriter = new FileWriter(output);
                BufferedWriter pemWriter = new BufferedWriter(fileWriter)) {
            pemWriter.write("-----BEGIN " + (password != null ? "ENCRYPTED " : "") + "PRIVATE KEY-----\n");
            pemWriter.write(Base64.getEncoder().encodeToString(content));
            pemWriter.write("\n-----END " + (password != null ? "ENCRYPTED " : "") + "PRIVATE KEY-----\n\n");
        }
    }

    public static void writeTruststoreToPem(List<X509Certificate> trustedCertificates, File output) throws Exception {
        try (FileWriter fileWriter = new FileWriter(output);
                BufferedWriter bufferedWriter = new BufferedWriter(fileWriter)) {
            // Write trusted certificates to truststore file
            for (X509Certificate certificate : trustedCertificates) {
                bufferedWriter.write("-----BEGIN CERTIFICATE-----\n");
                bufferedWriter.write(Base64.getEncoder().encodeToString(certificate.getEncoded()));
                bufferedWriter.write("\n-----END CERTIFICATE-----\n\n");
            }
        }
    }

    public static void writePrivateKeyAndCertificateToJKS(Map<String, CertificateHolder> certs, String password, File output)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        for (Map.Entry<String, CertificateHolder> entry : certs.entrySet()) {
            String alias = entry.getKey();
            keyStore.setKeyEntry(
                    alias,
                    entry.getValue().keys().getPrivate(),
                    entry.getValue().password(),
                    new Certificate[] { entry.getValue().certificate() });
        }

        FileOutputStream keyStoreFos = new FileOutputStream(output);
        keyStore.store(keyStoreFos, password.toCharArray());
        keyStoreFos.close();
    }

    public static void writeClientPrivateKeyAndCertificateToJKS(Map<String, CertificateHolder> certs, String password,
            File output) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        boolean hasAtLeastOneEntry = false;
        for (Map.Entry<String, CertificateHolder> entry : certs.entrySet()) {
            String alias = entry.getKey();
            if (entry.getValue().hasClient()) {
                hasAtLeastOneEntry = true;
                keyStore.setKeyEntry(
                        alias,
                        entry.getValue().clientKeys().getPrivate(),
                        entry.getValue().password(),
                        new Certificate[] { entry.getValue().clientCertificate() });
            }
        }

        if (hasAtLeastOneEntry) {
            FileOutputStream keyStoreFos = new FileOutputStream(output);
            keyStore.store(keyStoreFos, password.toCharArray());
            keyStoreFos.close();
        }
    }

    public static void writeClientTrustStoreToJKS(Map<String, CertificateHolder> certificates, File output, char[] password)
            throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);
        for (Map.Entry<String, CertificateHolder> entry : certificates.entrySet()) {
            trustStore.setCertificateEntry(entry.getKey(), entry.getValue().certificate());
        }
        FileOutputStream trustStoreFos = new FileOutputStream(output);
        trustStore.store(trustStoreFos, password);
        trustStoreFos.close();
    }

    public static void writeServerTrustStoreToJKS(Map<String, CertificateHolder> certificates, File output, char[] password)
            throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);

        boolean hasAtLeastOneEntry = false;

        for (Map.Entry<String, CertificateHolder> entry : certificates.entrySet()) {
            if (entry.getValue().hasClient()) {
                trustStore.setCertificateEntry(entry.getKey(), entry.getValue().clientCertificate());
                hasAtLeastOneEntry = true;
            }
        }

        if (hasAtLeastOneEntry) {
            FileOutputStream trustStoreFos = new FileOutputStream(output);
            trustStore.store(trustStoreFos, password);
            trustStoreFos.close();
        }
    }

    public static void writePrivateKeyAndCertificateToPKCS12(Map<String, CertificateHolder> certificates, File output,
            char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);

        for (Map.Entry<String, CertificateHolder> entry : certificates.entrySet()) {
            if (entry.getValue().issuer() != null) {
                keyStore.setCertificateEntry("issuer-" + entry.getKey(), entry.getValue().issuer().issuer());
            }
            keyStore.setKeyEntry(
                    entry.getKey(),
                    entry.getValue().keys().getPrivate(),
                    entry.getValue().password(),
                    new Certificate[] { entry.getValue().certificate() });
        }

        FileOutputStream keyStoreFos = new FileOutputStream(output);
        keyStore.store(keyStoreFos, password);
        keyStoreFos.close();
    }

    public static void writeClientPrivateKeyAndCertificateToPKCS12(Map<String, CertificateHolder> certificates, File output,
            char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);

        boolean hasAtLeastOneEntry = false;
        for (Map.Entry<String, CertificateHolder> entry : certificates.entrySet()) {
            if (entry.getValue().hasClient()) {
                hasAtLeastOneEntry = true;
                keyStore.setKeyEntry(
                        entry.getKey(),
                        entry.getValue().clientKeys().getPrivate(),
                        entry.getValue().password(),
                        new Certificate[] { entry.getValue().clientCertificate() });
            }

        }

        if (hasAtLeastOneEntry) {
            FileOutputStream keyStoreFos = new FileOutputStream(output);
            keyStore.store(keyStoreFos, password);
            keyStoreFos.close();
        }
    }

    public static void writeClientTrustStoreToPKCS12(Map<String, CertificateHolder> certificates, File output, char[] password)
            throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        for (Map.Entry<String, CertificateHolder> entry : certificates.entrySet()) {
            trustStore.setCertificateEntry(entry.getKey(), entry.getValue().certificate());
        }
        FileOutputStream trustStoreFos = new FileOutputStream(output);
        trustStore.store(trustStoreFos, password);
        trustStoreFos.close();
    }

    public static void writeServerTrustStoreToPKCS12(Map<String, CertificateHolder> certificates, File output, char[] password)
            throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);

        boolean hasAtLeastOneEntry = false;
        for (Map.Entry<String, CertificateHolder> entry : certificates.entrySet()) {
            if (entry.getValue().hasClient()) {
                trustStore.setCertificateEntry(entry.getKey(), entry.getValue().clientCertificate());
                hasAtLeastOneEntry = true;
            }
        }

        if (hasAtLeastOneEntry) {
            FileOutputStream trustStoreFos = new FileOutputStream(output);
            trustStore.store(trustStoreFos, password);
            trustStoreFos.close();
        }
    }

    public static KeyPair loadPrivateKey(File keyFile) throws Exception {
        try (BufferedReader reader = new BufferedReader(new FileReader(keyFile));
                PEMParser pemParser = new PEMParser(reader)) {
            Object obj = pemParser.readObject();
            if (obj instanceof KeyPair) {
                return (KeyPair) obj;
            } else {
                throw new IllegalArgumentException("Invalid PEM file format");
            }
        }
    }

    public static X509Certificate loadCertificate(File certificateFile) throws Exception {
        if (certificateFile.getName().endsWith(".der")) {
            try (FileInputStream fis = new FileInputStream(certificateFile)) {
                var bytes = fis.readAllBytes();
                // Create a CertificateFactory and parse the DER-encoded bytes into an X509Certificate
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(bytes));
            }
        } else if (certificateFile.getName().endsWith(".pem") || certificateFile.getName().endsWith(".crt")) {
            try (BufferedReader reader = new BufferedReader(new FileReader(certificateFile));
                    PEMParser pemParser = new PEMParser(reader)) {
                Object obj = pemParser.readObject();
                if (obj instanceof X509Certificate) {
                    return (X509Certificate) obj;
                }
                if (obj instanceof X509CertificateHolder) {
                    return new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) obj);
                } else {
                    throw new IllegalArgumentException("Invalid PEM file format: " + obj);
                }
            }
        } else {
            throw new IllegalArgumentException("Unsupported certificate format. Only DER and PEM/CRT are supported.");
        }
    }
}
