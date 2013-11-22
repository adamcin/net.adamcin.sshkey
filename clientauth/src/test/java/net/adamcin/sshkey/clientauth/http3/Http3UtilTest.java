package net.adamcin.sshkey.clientauth.http3;

import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.sshkey.api.DefaultKeychain;
import net.adamcin.sshkey.api.Signer;
import net.adamcin.sshkey.clientauth.HttpServerTestBody;
import net.adamcin.sshkey.jce.JCEKey;
import net.adamcin.sshkey.jce.KeyFormat;
import net.adamcin.sshkey.testutil.KeyTestUtil;
import org.apache.commons.httpclient.HttpClient;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;

import static org.junit.Assert.*;

public class Http3UtilTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(Http3UtilTest.class);


    @Test
    public void testLogin() {
        TestBody.test(new HttpServerTestBody() {
            @Override protected void execute() throws Exception {
                setServlet(new AdminServlet());

                KeyPair keyPair = KeyTestUtil.getKeyPairFromProperties("b2048", "id_rsa");

                DefaultKeychain provider = new DefaultKeychain();
                provider.add(new JCEKey(KeyFormat.SSH_RSA, keyPair));

                Signer signer = new Signer(provider);
                HttpClient client = new HttpClient();
                assertTrue(
                        "should return 200", Http3Util.login(
                        String.format("http://localhost:%d/index.html", getPort()),
                        signer, "admin", 200, client)
                );
            }
        });
    }
}
