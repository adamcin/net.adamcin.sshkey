package net.adamcin.sshkey.commons;

import com.jcraft.jsch.Identity;
import com.jcraft.jsch.JSch;
import net.adamcin.commons.testing.junit.FailUtil;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

import static org.junit.Assert.*;

public class PublicKeyTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(PublicKeyTest.class);

    @Test
    public void testSignature() {

        String sessionId = "sessionId";
        Challenge challenge = new Challenge("myRealm", "someFingerprint", sessionId, "localhost", "test");

        Reader reader = null;
        try {
            roundTrip(challenge, sessionId, "b1024", "id_rsa", null);
            roundTrip(challenge, sessionId, "b1024", "id_dsa", null);
            roundTrip(challenge, sessionId, "b2048", "id_rsa", null);
            roundTrip(challenge, sessionId, "b4096", "id_rsa", null);
            roundTrip(challenge, sessionId, "withpass", "id_rsa", "dummydummy");
            roundTrip(challenge, sessionId, "withpass", "id_dsa", "dummydummy");
        } catch (Exception e) {
            FailUtil.sprintFail(e);
        } finally {
            IOUtils.closeQuietly(reader);
        }
    }

    public void roundTrip(Challenge challenge, String sessionId, String parentName, String keyName, String passphrase)
            throws Exception {

        PublicKey key = readPublicKey(parentName, keyName);

        String sig = sign(challenge.getHash(), parentName, keyName, passphrase);

        Authorization packet = new Authorization(sessionId, sig);

        assertTrue("round trip " + parentName + "/" + keyName, key.verify(challenge, packet));
    }

    public PublicKey readPublicKey(String parentName, String keyName) throws IOException {
        InputStream is = null;

        try {
            is = new FileInputStream(KeyTestUtil.getPublicKeyAsFile(parentName, keyName));
            return PublicKey.readKeys(new InputStreamReader(is)).get(0);
        } finally {
            IOUtils.closeQuietly(is);
        }
    }

    public String sign(byte[] data, String parentName, String keyName, String passphrase) {

        JSch jsch = new JSch();
        try {
            jsch.removeAllIdentity();

            File tempPriv = KeyTestUtil.getPrivateKeyAsFile(parentName, keyName);

            if (passphrase == null) {
                jsch.addIdentity(tempPriv.getAbsolutePath());
            } else {
                jsch.addIdentity(tempPriv.getAbsolutePath(), passphrase);
            }

            Identity identity = (Identity) jsch.getIdentityRepository().getIdentities().firstElement();
            byte[] sig = identity.getSignature(data);

            return Util.toBase64(sig);
        } catch (Exception e) {
            FailUtil.sprintFail(e);
        }

        return null;
    }
}
