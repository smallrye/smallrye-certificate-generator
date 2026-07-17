package io.smallrye.certs.maven;

import io.smallrye.certs.AliasRequest;
import io.smallrye.certs.CertificateGenerator;
import io.smallrye.certs.CertificateRequest;
import io.smallrye.certs.Format;
import io.smallrye.certs.KeyAlgorithm;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.time.Duration;
import java.util.List;

@Mojo(name = "generate", defaultPhase = LifecyclePhase.GENERATE_TEST_RESOURCES, threadSafe = true, requiresProject = true)
public class CertificatesGeneratorMojo extends AbstractMojo {

    @Parameter(required = true)
    private List<CertificateRequestParameter> certificates;

    @Parameter(property = "certificate-generator.outputDirectory", defaultValue = "${project.build.directory}/certificates")
    private String outputDirectory;

    @Parameter(property = "certificate-generator.replaceIfExists", defaultValue = "false")
    private boolean replaceIfExists;

    @Override
    public void execute() throws MojoExecutionException {
        getLog().info("Generating certificates");

        var out = new File(outputDirectory);
        if (!out.isDirectory()) {
            out.mkdirs();
        }

        try {
            CertificateGenerator generator = new CertificateGenerator(new File(outputDirectory).toPath(), replaceIfExists);
            for (CertificateRequestParameter request : certificates) {
                CertificateRequest cr = new CertificateRequest()
                        .withName(request.getName())
                        .withFormats(request.getFormats().stream().map(String::toUpperCase).map(Format::valueOf).toList())
                        .withClientCertificate(request.isClient())
                        .withCN(request.getCn())
                        .withPassword(request.getPassword())
                        .withDuration(Duration.ofDays(request.getDuration()))
                        .withKeyAlgorithm(KeyAlgorithm.valueOf(request.getKeyAlgorithm()));

                if (request.getSubjectAlternativeNames() != null) {
                    for (String subjectAlternativeName : request.getSubjectAlternativeNames()) {
                        cr.withSubjectAlternativeName(subjectAlternativeName);
                    }
                }

                if (request.getAliases() != null) {
                    for (AliasParameter alias : request.getAliases()) {
                        AliasRequest req = new AliasRequest()
                                .withClientCertificate(alias.isClient())
                                .withPassword(alias.getPassword())
                                .withCN(alias.getCn())
                                .withKeyAlgorithm(KeyAlgorithm.valueOf(alias.getKeyAlgorithm()));

                        if (alias.getSubjectAlternativeNames() != null) {
                            for (String subjectAlternativeName : alias.getSubjectAlternativeNames()) {
                                req.withSubjectAlternativeName(subjectAlternativeName);
                            }
                        }

                        cr.withAlias(alias.getName(), req);

                    }
                }

                generator.generate(cr);
            }

        } catch (Exception e) {
            throw new MojoExecutionException("Unable to generate certificates", e);
        }
    }

    public void setCertificates(List<CertificateRequestParameter> requests) {
        this.certificates = requests;
    }
}
