import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.jscep.client.Client;
import org.jscep.client.DefaultCallbackHandler;
import org.jscep.client.EnrollmentResponse;
import org.jscep.client.verification.OptimisticCertificateVerifier;
import org.jscep.transport.response.Capabilities;

/**
 * Drives the SCEP endpoint with jscep, an independent implementation of the client side.
 * Usage: Conformance URL CHALLENGE. Prints one "PASS ..." line per check, and exits 1 on the first failure.
 */
public class Conformance {
    static void check(boolean ok, String what) {
        if (!ok) {
            System.out.println("FAIL " + what);
            System.exit(1);
        }
        System.out.println("PASS " + what);
    }

    static PKCS10CertificationRequest csr(String subject, KeyPair keys, String challenge) throws Exception {
        PKCS10CertificationRequestBuilder builder =
            new JcaPKCS10CertificationRequestBuilder(new X500Principal(subject), keys.getPublic());
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, new DERPrintableString(challenge));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate());
        return builder.build(signer);
    }

    static X509Certificate selfSigned(String subject, KeyPair keys) throws Exception {
        long day = 24L * 60 * 60 * 1000;
        X500Principal name = new X500Principal(subject);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            name, BigInteger.ONE, new Date(System.currentTimeMillis() - day),
            new Date(System.currentTimeMillis() + day), name, keys.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static void main(String[] args) throws Exception {
        Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
        URL url = new URL(args[0]);
        String challenge = args[1];
        boolean renew = args.length < 3 || !args[2].equals("norenew");
        Client client = new Client(url, new DefaultCallbackHandler(new OptimisticCertificateVerifier()));

        Capabilities caps = client.getCaCapabilities();
        check(caps.isPostSupported(), "the CA supports POST");
        check(caps.getStrongestSignatureAlgorithm().startsWith("SHA"), "a SHA signature algorithm is offered");

        CertStore store = client.getCaCertificate();
        Collection<?> certs = store.getCertificates(null);
        check(certs.size() == 2, "GetCACert returns the RA and the CA (" + certs.size() + ")");

        // First enrollment: a self-signed certificate for the key, and the challenge.
        KeyPair keys = rsa();
        String subject = "CN=jscep-device";
        X509Certificate requester = selfSigned(subject, keys);
        EnrollmentResponse first = client.enrol(requester, keys.getPrivate(), csr(subject, keys, challenge));
        check(first.isSuccess(), "enrollment with the right challenge succeeds");
        X509Certificate issued = (X509Certificate) first.getCertStore().getCertificates(null).iterator().next();
        check(issued.getSubjectX500Principal().getName().contains("CN=jscep-device"), "the subject is the requested CN");
        check(issued.getPublicKey().equals(keys.getPublic()), "the certificate is for the requested key");

        // GetCert: the issued certificate can be fetched again by serial.
        CertStore again = client.getCertificate(issued, keys.getPrivate(), issued.getSerialNumber());
        check(again.getCertificates(null).size() == 1, "GetCert returns the certificate");

        if (renew) {
        // Re-enrollment: signed with the certificate we were issued, with no valid challenge.
        EnrollmentResponse renewed = client.enrol(issued, keys.getPrivate(), csr(subject, keys, "not-the-challenge"));
        check(renewed.isSuccess(), "re-enrollment signed by the issued certificate succeeds");
        X509Certificate second = (X509Certificate) renewed.getCertStore().getCertificates(null).iterator().next();
        check(!second.getSerialNumber().equals(issued.getSerialNumber()), "re-enrollment issues a new serial");
        }

        // A wrong challenge is a FAILURE with badRequest, not an exception.
        KeyPair other = rsa();
        EnrollmentResponse wrong = client.enrol(selfSigned("CN=intruder", other), other.getPrivate(), csr("CN=intruder", other, "wrong"));
        check(wrong.isFailure(), "a wrong challenge fails");
        check(wrong.getFailInfo().toString().equalsIgnoreCase("badRequest"), "with failInfo badRequest (" + wrong.getFailInfo() + ")");
    }
}
