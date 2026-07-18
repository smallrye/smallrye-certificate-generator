package io.smallrye.certs.chain;

import java.io.File;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import io.smallrye.certs.CertificateUtils;
import io.smallrye.certs.KeyAlgorithm;

public class CertificateChainGenerator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private String cn = "localhost";

    private List<String> sans = List.of("DNS:localhost");

    private List<String> caSans = List.of();

    private KeyAlgorithm keyAlgorithm = KeyAlgorithm.RSA_2048;

    private final File baseDir;

    public CertificateChainGenerator(File baseDir) {
        this.baseDir = baseDir;
        if (!baseDir.isDirectory()) {
            baseDir.mkdirs();
        }
    }

    /**
     * Configure the common name of the "leaf" certificate.
     *
     * @param cn the common name, by default `localhost`
     * @return the current generator instance
     */
    public CertificateChainGenerator withCN(String cn) {
        this.cn = cn;
        return this;
    }

    /**
     * Configure the Subject Alternative Names of the "leaf" certificate.
     *
     * @param san the list of SAN, by default `DNS:localhost`
     * @return the current generator instance
     */
    public CertificateChainGenerator withSAN(List<String> san) {
        this.sans = san == null ? List.of() : san;
        return this;
    }

    /**
     * Configure the Subject Alternative Names of the root and intermediate CA certificates.
     *
     * @param caSans the list of SAN, by default empty (no SANs on CA certs)
     * @return the current generator instance
     */
    public CertificateChainGenerator withCaSAN(List<String> caSans) {
        this.caSans = caSans == null ? List.of() : caSans;
        return this;
    }

    public CertificateChainGenerator withKeyAlgorithm(KeyAlgorithm keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
        return this;
    }

    public void generate() throws Exception {

        // Generate root certificate
        var rootKeyPair = generateKeyPair();
        var rootCertificate = generateRootCertificate(rootKeyPair);

        // Generate intermediary certificate
        var intermediaryKeyPair = generateKeyPair();
        var intermediaryCertificate = generateIntermediaryCertificate(intermediaryKeyPair, rootKeyPair, rootCertificate);

        // Generate leaf certificate
        var leafKeyPair = generateKeyPair();
        var leafCertificate = generateLeafCertificate(leafKeyPair, intermediaryKeyPair, intermediaryCertificate);

        // Write the certificates to files
        // root.crt, root.key, intermediary.crt, intermediary.key, cn.crt, cn.key
        CertificateUtils.writeCertificateToPEM(rootCertificate, new File(baseDir, "root.crt"));
        CertificateUtils.writePrivateKeyToPem(rootKeyPair.getPrivate(), null, new File(baseDir, "root.key"));

        CertificateUtils.writeCertificateToPEM(intermediaryCertificate, new File(baseDir, "intermediate.crt"));
        CertificateUtils.writePrivateKeyToPem(intermediaryKeyPair.getPrivate(), null, new File(baseDir, "intermediate.key"));

        CertificateUtils.writeCertificateToPEM(leafCertificate, new File(baseDir, cn + ".crt"), intermediaryCertificate);
        CertificateUtils.writePrivateKeyToPem(leafKeyPair.getPrivate(), null, new File(baseDir, cn + ".key"));
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        return keyAlgorithm.generateKeyPairWithBouncyCastleProvider();
    }

    private X509Certificate generateRootCertificate(KeyPair rootKeyPair)
            throws CertIOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        var keyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(rootKeyPair.getPublic().getEncoded()));
        var issuer = new X500Name("CN=quarkus-root,O=Quarkus Development");
        var subject = new X500Name("CN=root");
        var yesterday = new Date(System.currentTimeMillis() - 86400000);
        var oneYear = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000); // 1 year
        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis()),
                yesterday,
                oneYear,
                subject,
                keyInfo);

        certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        certGen.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(rootKeyPair.getPublic()));

        if (!caSans.isEmpty()) {
            certGen.addExtension(Extension.subjectAlternativeName, false, CertificateUtils.toSanSequence(caSans));
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(keyAlgorithm.signatureAlgorithm());
        ContentSigner signer = contentSignerBuilder.build(rootKeyPair.getPrivate());
        X509CertificateHolder holder = certGen.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private X509Certificate generateIntermediaryCertificate(KeyPair intermediaryKeyPair, KeyPair rootKeyPair,
            X509Certificate rootCertificate)
            throws NoSuchAlgorithmException, CertIOException, OperatorCreationException, CertificateException {
        var keyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(intermediaryKeyPair.getPublic().getEncoded()));
        var yesterday = new Date(System.currentTimeMillis() - 86400000);
        var oneYear = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000); // 1 year
        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                new X500Name(rootCertificate.getSubjectX500Principal().getName()),
                BigInteger.valueOf(System.currentTimeMillis()),
                yesterday,
                oneYear,
                new X500Name("CN=intermediary"),
                keyInfo);

        certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature));
        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        certGen.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(intermediaryKeyPair.getPublic()));

        if (!caSans.isEmpty()) {
            certGen.addExtension(Extension.subjectAlternativeName, false, CertificateUtils.toSanSequence(caSans));
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(keyAlgorithm.signatureAlgorithm());
        ContentSigner contentSigner = contentSignerBuilder.build(rootKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certGen.build(contentSigner));
    }

    private X509Certificate generateLeafCertificate(KeyPair leafKeyPair, KeyPair intermediaryKeyPair,
            X509Certificate intermediaryCertificate)
            throws NoSuchAlgorithmException, CertIOException, OperatorCreationException, CertificateException {
        var keyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(leafKeyPair.getPublic().getEncoded()));
        var before = Instant.now().minus(2, ChronoUnit.DAYS);
        var after = Instant.now().plus(2, ChronoUnit.DAYS);

        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                new X500Name(intermediaryCertificate.getSubjectX500Principal().getName()),
                BigInteger.valueOf(System.currentTimeMillis()),
                new java.util.Date(before.toEpochMilli()),
                new java.util.Date(after.toEpochMilli()),
                new X500Name("CN=" + cn),
                keyInfo);

        certGen.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment
                        | KeyUsage.keyAgreement | KeyUsage.nonRepudiation));
        certGen.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(leafKeyPair.getPublic()));

        if (!sans.isEmpty()) {
            certGen.addExtension(Extension.subjectAlternativeName, false, CertificateUtils.toSanSequence(sans));
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(keyAlgorithm.signatureAlgorithm());
        ContentSigner contentSigner = contentSignerBuilder.build(intermediaryKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certGen.build(contentSigner));
    }

}
