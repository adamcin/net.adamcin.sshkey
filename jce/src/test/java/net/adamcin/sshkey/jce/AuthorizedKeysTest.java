package net.adamcin.sshkey.jce;

import net.adamcin.commons.testing.junit.FailUtil;
import net.adamcin.sshkey.api.Authorization;
import net.adamcin.sshkey.api.Base64;
import net.adamcin.sshkey.api.Challenge;
import net.adamcin.sshkey.api.Key;
import net.adamcin.sshkey.api.Signer;
import net.adamcin.sshkey.api.Verifier;
import net.adamcin.sshkey.jce.AuthorizedKeys.*;
import net.adamcin.sshkey.testutil.KeyTestUtil;
import net.adamcin.sshkey.api.DefaultKeychain;
import org.junit.Test;

import java.io.File;
import java.security.KeyPair;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;


import static org.junit.Assert.*;

public class AuthorizedKeysTest {

    private static final String TEST_AUTHORIZED_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC+Fz0pqK+XoCcukPhnPD+M1zb+FImbh5Lu3pkfW5DM67B6Hr9Q28LuWgNTfLqUn9o01W0TYzXDxtKG9psGuQ0wFJmqYJNbP6eRB3gimcr+C/eyy7N/evs8E36iMi7Si1piPd7QJ5l3D/tThI5cAACHYN0uqwphpXt4Lw2OZxIAQw== dummy@nowhere";

    @Test
    public void testParseAuthorizedKey() {

        try {
            AuthorizedKeys.AuthorizedKey authorizedKey = AuthorizedKeys.parseAuthorizedKey(TEST_AUTHORIZED_KEY);
            assertNotNull("authorizedKey should not be null", authorizedKey);
            assertEquals("authorizedKey format should be", "ssh-rsa", authorizedKey.getFormat());
            assertEquals(
                    "authorizedKey encodedKey should be",
                    "AAAAB3NzaC1yc2EAAAADAQABAAAAgQC+Fz0pqK+XoCcukPhnPD+M1zb+FImbh5Lu3pkfW5DM67B6Hr9Q28LuWgNTfLqUn9o01W0TYzXDxtKG9psGuQ0wFJmqYJNbP6eRB3gimcr+C/eyy7N/evs8E36iMi7Si1piPd7QJ5l3D/tThI5cAACHYN0uqwphpXt4Lw2OZxIAQw==",
                    authorizedKey.getEncodedKey()
            );
            assertEquals("authorizedKey comment should be", "dummy@nowhere", authorizedKey.getComment());

            File rsaPubKeyFile = KeyTestUtil.getPublicKeyAsFile("b1024", "id_rsa");
            List<AuthorizedKeys.AuthorizedKey> authorizedKeys = AuthorizedKeys.parseAuthorizedKeys(rsaPubKeyFile);
            assertEquals("rsaPubKeyFile should only contain one pubkey", 1, authorizedKeys.size());
        } catch (Exception e) {
            FailUtil.sprintFail(e);
        }
    }

    @Test
    public void testAuthorizedKeysVerifier() {
        compareAuthorizedKeyToKeyPair("b1024", "id_dsa", KeyFormat.SSH_DSS);
        compareAuthorizedKeyToKeyPair("b1024", "id_rsa", KeyFormat.SSH_RSA);
        compareAuthorizedKeyToKeyPair("b2048", "id_rsa", KeyFormat.SSH_RSA);
        compareAuthorizedKeyToKeyPair("b4096", "id_rsa", KeyFormat.SSH_RSA);
        compareAuthorizedKeyToKeyPair("withpass", "id_dsa", KeyFormat.SSH_DSS);
        compareAuthorizedKeyToKeyPair("withpass", "id_rsa", KeyFormat.SSH_RSA);
    }

    public void compareAuthorizedKeyToKeyPair(String parentName, String keyName, KeyFormat format) {
        final String id = "[" + parentName + "/" + keyName + "] ";

        try {
            List<AuthorizedKey> keys = AuthorizedKeys.parseAuthorizedKeys(
                    KeyTestUtil.getPublicKeyAsFile(parentName, keyName)
            );

            AuthorizedKey key = keys.get(0);

            PublicPair publicPair = AuthorizedKeys.readPublicPair(Base64.fromBase64String(key.getEncodedKey()));

            assertEquals(id + "public pair should be KeyFormat", format, publicPair.getFormat());

            KeyPair keyPair = KeyTestUtil.getKeyPairFromProperties(parentName, keyName);

            if (format == KeyFormat.SSH_RSA) {
                assertTrue(
                        id + "keyPair.getPublic() should be instance of RSAPublicKey",
                        keyPair.getPublic() instanceof RSAPublicKey
                );
                assertTrue(
                        "publicPair.getSpec() should be instance of RSAPublicKeySpec",
                        publicPair.getSpec() instanceof RSAPublicKeySpec
                );

                RSAPublicKeySpec publicPairSpec = (RSAPublicKeySpec) publicPair.getSpec();
                RSAPublicKeySpec keyPairSpec = format.getKeyFactory().getKeySpec(
                        keyPair.getPublic(), RSAPublicKeySpec.class
                );

                assertEquals(
                        "public exponents should match", keyPairSpec.getPublicExponent(),
                        publicPairSpec.getPublicExponent()
                );
                assertEquals("moduli should match", keyPairSpec.getModulus(), publicPairSpec.getModulus());
            } else if (format == KeyFormat.SSH_DSS) {
                assertTrue(
                        id + "keyPair.getPublic() should be instance of DSAPublicKey",
                        keyPair.getPublic() instanceof DSAPublicKey
                );
                assertTrue(
                        id + "publicPair.getSpec() should be instance of DSAPublicKeySpec",
                        publicPair.getSpec() instanceof DSAPublicKeySpec
                );

                DSAPublicKeySpec publicPairSpec = (DSAPublicKeySpec) publicPair.getSpec();
                DSAPublicKeySpec keyPairSpec = format.getKeyFactory().getKeySpec(
                        keyPair.getPublic(), DSAPublicKeySpec.class
                );

                assertEquals(id + "G should match", keyPairSpec.getG(), publicPairSpec.getG());
                assertEquals(id + "P should match", keyPairSpec.getP(), publicPairSpec.getP());
                assertEquals(id + "Q should match", keyPairSpec.getQ(), publicPairSpec.getQ());
                assertEquals(id + "Y should match", keyPairSpec.getY(), publicPairSpec.getY());
            } else {
                throw new IllegalArgumentException("unknown key format");
            }

            Key jceKey = new JCEKey(format, keyPair);
            Key akKey = AuthorizedKeys.createPublicIdentity(publicPair);

            assertEquals(id + "fingerprints should match", jceKey.getId(), akKey.getId());

            DefaultKeychain signingAndVerifying = new DefaultKeychain(Arrays.asList(jceKey));
            DefaultKeychain verifying = new DefaultKeychain(Arrays.asList(akKey));

            Signer signer = new Signer(signingAndVerifying);
            Verifier sameKeyVerifier = new Verifier(signingAndVerifying);
            Verifier publicKeyVerifier = new Verifier(verifying);

            final String realm = getClass().getName();
            final String host = "localhost";
            final String userAgent = "jUnit";
            final String sessionId = "session";
            final String fingerprint = jceKey.getId();

            Challenge challenge = new Challenge(realm, fingerprint, sessionId, host, userAgent);

            Authorization authorization = signer.sign(challenge);

            assertTrue(id + "same key verifier should verify", sameKeyVerifier.verify(challenge, authorization));
            assertTrue(id + "public key verifier should verify", publicKeyVerifier.verify(challenge, authorization));

        } catch (Exception e) {
            FailUtil.sprintFail(e);
        }
    }
}
