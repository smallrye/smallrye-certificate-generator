package io.smallrye.certs.ca;

import static io.smallrye.certs.ca.LinuxCAInstaller.installCAOnLinux;
import static io.smallrye.certs.ca.MacCAInstaller.installCAOnMac;
import static io.smallrye.certs.ca.WindowsCAInstaller.installCAOnWindows;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.WARNING;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import io.smallrye.common.os.OS;

public class CaGenerator {

    static System.Logger LOGGER = System.getLogger(CaGenerator.class.getName());

    public static final String KEYSTORE_KEY_ENTRY = "key";
    public static final String KEYSTORE_CERT_ENTRY = "ca";
    private final File ca;
    private final File key;
    private final File ks;
    private final String password;
    private volatile X509Certificate generatedCA;
    private String cn;

    /**
     * Create a new instance of {@link CaGenerator}.
     * <p>
     *
     * @param ca the file where the CA certificate should be stored (PEM file), must not be null
     * @param key the file where the private key should be stored (PEM file), must not be null
     * @param ks the file where the keystore should be stored (P12 file), must not be null
     * @param password the password to protect the keystore, and the private key, must not be null or empty
     */
    public CaGenerator(File ca, File key, File ks, String password) {
        Security.addProvider(new BouncyCastleProvider());
        this.ca = ca;
        this.key = key;
        this.ks = ks;
        this.password = password;
    }

    /**
     * Generate a Root CA certificate and store it in a keystore.
     * <p>
     * This method writes the CA certificate to a PEM file, the private key to a PEM file, and the key and cert to a PKCS12
     * keystore.
     * It also returns the {@code X509Certificate} instance.
     *
     * @param cn the common name of the certificate, must not be null
     * @param org the organization, can be null, must not be empty
     * @param unit the organizational unit, can be null, must not be empty
     * @param location the location, can be null, must not be empty
     * @param state the state, can be null, must not be empty
     * @param country, the country, can be null, must not be empty
     * @return the generated CA certificate
     * @throws Exception if the generation fails
     */
    public X509Certificate generate(String cn, String org, String unit, String location, String state, String country)
            throws Exception {
        String issuerText = "CN=" + cn;
        if (org != null) {
            issuerText += ",O=" + org;
        }
        String subjectText = issuerText;
        if (unit != null) {
            subjectText += ",OU=" + unit;
        }
        if (location != null) {
            subjectText += ",L=" + location;
        }
        if (state != null) {
            subjectText += ",ST=" + state;
        }
        if (country != null) {
            subjectText += ",C=" + country;
        }

        var issuer = new X500Name(issuerText);
        var subject = new X500Name(subjectText);
        var yesterday = new Date(System.currentTimeMillis() - 86400000);
        var oneYear = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000); // 1 year

        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        var keyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(keyPair.getPublic().getEncoded()));

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis()),
                yesterday,
                oneYear,
                subject,
                keyInfo);

        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0)); // CA + Path Length
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
        var cert = new JcaX509CertificateConverter()
                .getCertificate(builder.build(contentSignerBuilder.build(keyPair.getPrivate())));

        // Save the Root CA certificate to a pem file
        try (FileWriter fileWriter = new FileWriter(ca);
                BufferedWriter pemWriter = new BufferedWriter(fileWriter)) {
            pemWriter.write("-----BEGIN CERTIFICATE-----\n");
            pemWriter.write(Base64.getEncoder().encodeToString(cert.getEncoded()));
            pemWriter.write("\n-----END CERTIFICATE-----\n\n");

        }

        try (FileWriter fileWriter = new FileWriter(key);
                BufferedWriter pemWriter = new BufferedWriter(fileWriter)) {
            pemWriter.write("-----BEGIN PRIVATE KEY-----\n");
            pemWriter.write(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            pemWriter.write("\n-----END PRIVATE KEY-----\n\n");
        }

        // Store the key and cert in a P12 keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(KEYSTORE_KEY_ENTRY, keyPair.getPrivate(), password.toCharArray(),
                new java.security.cert.Certificate[] { cert });
        keyStore.setCertificateEntry(KEYSTORE_CERT_ENTRY, cert);
        try (var fos = new FileOutputStream(ks)) {
            keyStore.store(fos, password.toCharArray());
        }

        // Adjust permissions
        if (OS.MAC.isCurrent() || OS.LINUX.isCurrent()) {
            Set<PosixFilePermission> ownerWritable = PosixFilePermissions.fromString("rw-r--r--");
            Set<PosixFilePermission> ownerRW = PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(ca.toPath(), ownerWritable);
            Files.setPosixFilePermissions(key.toPath(), ownerRW);
            Files.setPosixFilePermissions(ks.toPath(), ownerRW);
        }

        LOGGER.log(INFO, "🔥 Root CA certificate generated successfully!");

        this.generatedCA = cert;
        this.cn = cn; // Required for the installation in the system truststore on MacOS
        return cert;
    }

    /**
     * Generate a PKCS#12 truststore containing the CA certificate.
     * <p>
     * The generated truststore is a PKCS12 file containing the CA certificate at the entry {@code ca}.
     * The truststore is protected by the password provided when creating the instance of {@link CaGenerator}.
     *
     * @param trustStore the truststore file, must not be null
     * @throws KeyStoreException if the truststore cannot be generated
     */
    public void generateTrustStore(File trustStore) throws Exception {
        if (!ks.isFile() || generatedCA == null) {
            throw new IllegalStateException("The keystore has not been generated yet, call `generate` first");
        }

        LOGGER.log(INFO, "🔥 Generating p12 truststore...");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setCertificateEntry(KEYSTORE_CERT_ENTRY, generatedCA);
        try (var fos = new FileOutputStream(trustStore)) {
            keyStore.store(fos, password.toCharArray());
        }
        LOGGER.log(INFO, "🔥 Truststore generated successfully: {0}.", trustStore.getAbsolutePath());
    }

    /**
     * Install the CA certificate in the system truststore.
     * <p>
     * The behavior of this method depends on the operating system.
     * It requires elevated privileges.
     */
    public void installToSystem() throws Exception {
        if (!ks.isFile() || generatedCA == null) {
            throw new IllegalStateException("The keystore has not been generated yet, call `generate` first");
        }

        LOGGER.log(INFO, "🔥 Installing the CA certificate in the system truststore...");

        if (OS.MAC.isCurrent()) {
            installCAOnMac(cn, ca);
        } else if (OS.WINDOWS.isCurrent()) {
            installCAOnWindows(cn, ca);
        } else if (OS.LINUX.isCurrent()) {
            installCAOnLinux(cn, ca);
        } else {
            LOGGER.log(WARNING, "❌ Unsupported operating system: {0}", OS.current());
        }

    }

}
