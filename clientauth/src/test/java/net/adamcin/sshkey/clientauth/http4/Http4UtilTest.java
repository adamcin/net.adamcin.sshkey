package net.adamcin.sshkey.clientauth.http4;

import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.sshkey.api.Signer;
import net.adamcin.sshkey.clientauth.HttpServerTestBody;
import net.adamcin.sshkey.simple.JCEIdentity;
import net.adamcin.sshkey.simple.KeyFormat;
import net.adamcin.sshkey.simple.SimpleIdentityProvider;
import net.adamcin.sshkey.testutil.KeyTestUtil;
import org.apache.http.impl.client.DefaultHttpClient;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;

import static org.junit.Assert.*;

public class Http4UtilTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(Http4UtilTest.class);


    @Test
    public void testLogin() {
        TestBody.test(new HttpServerTestBody() {
            @Override protected void execute() throws Exception {
                setServlet(new AdminServlet());

                KeyPair keyPair = KeyTestUtil.getKeyPairFromProperties("b2048", "id_rsa");

                SimpleIdentityProvider provider = new SimpleIdentityProvider();
                provider.add(new JCEIdentity(KeyFormat.SSH_RSA, keyPair));

                Signer signer = new Signer(provider);
                DefaultHttpClient client = new DefaultHttpClient();
                assertTrue(
                        "should return 200", Http4Util.login(
                        String.format("http://localhost:%d/index.html", getPort()),
                        signer, "admin", 200, client, null
                )
                );
            }
        });
    }
}
