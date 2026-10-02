package io.smallrye.certs.pem.parsers;

import io.smallrye.certs.pem.der.ASN1ObjectIdentifier;
import io.smallrye.certs.pem.der.DerParser;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PKCS8Parser implements PKPemParser {

    private static final String PKCS8_START = "-+BEGIN\\s+PRIVATE\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+";

    private static final String PKCS8_END = "-+END\\s+PRIVATE\\s+KEY[^-]*-+";

    private static final Pattern PATTERN = Pattern.compile(PKCS8_START + BASE64_TEXT + PKCS8_END, Pattern.CASE_INSENSITIVE);

    public PKCS8Parser() {
    }

    @Override
    public PrivateKey getKey(String content, String password) {
        try {
            Matcher matcher = PATTERN.matcher(content);
            if (matcher.find()) {
                var encoded = matcher.group(BASE64_TEXT_GROUP);
                var decoded = decodeBase64(encoded);
                return extract(decoded, password);
            }
        } catch (Exception e) {
            return null;
        }
        // Does not match PKCS8 encrypted pattern
        return null;
    }

    private PrivateKey extract(byte[] decoded, String ignored) {
        DerParser parser = new DerParser(decoded);
        if (parser.type() != DerParser.Type.CONSTRUCTED || parser.tag() != DerParser.Tag.SEQUENCE.number()) {
            throw new IllegalArgumentException("Key spec should be an encoded sequence");
        }
        var version = parser.next();
        if (version.type() != DerParser.Type.PRIMITIVE || version.tag() != DerParser.Tag.INTEGER.number()) {
            throw new IllegalArgumentException("Key spec should contain the (integer) version");
        }

        var seq = parser.next();
        if (seq.type() != DerParser.Type.CONSTRUCTED || seq.tag() != DerParser.Tag.SEQUENCE.number()) {
            throw new IllegalArgumentException("Key spec should contain a sequence");
        }

        var algorithmId = seq.next();
        if (algorithmId.type() != DerParser.Type.PRIMITIVE || algorithmId.tag() != DerParser.Tag.OBJECT_IDENTIFIER.number()) {
            throw new IllegalArgumentException("Key spec container expects an object identifier as algorithm id");
        }
        String algorithm = ASN1ObjectIdentifier.getAlgorithmId(algorithmId.content().getBytes());
        var spec = (algorithm != null) ? new PKCS8EncodedKeySpec(decoded, algorithm) : new PKCS8EncodedKeySpec(decoded);

        for (String algo : ALGORITHMS) {
            try {
                KeyFactory factory = KeyFactory.getInstance(algo);
                return factory.generatePrivate(spec);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                // Ignore
            }
        }
        return null;
    }
}
