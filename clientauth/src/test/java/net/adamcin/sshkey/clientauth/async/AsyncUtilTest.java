package net.adamcin.sshkey.clientauth.async;

import com.ning.http.client.AsyncCompletionHandler;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.AsyncHttpClientConfig;
import com.ning.http.client.Response;
import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.sshkey.api.DefaultKeychain;
import net.adamcin.sshkey.api.Signer;
import net.adamcin.sshkey.clientauth.HttpServerTestBody;
import net.adamcin.sshkey.jce.JCEKey;
import net.adamcin.sshkey.jce.KeyFormat;
import net.adamcin.sshkey.testutil.KeyTestUtil;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;

import static org.junit.Assert.*;

public class AsyncUtilTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(AsyncUtilTest.class);

    private static final RequestBuilderDecorator FOLLOW_REDIRECTS_DECORATOR = new RequestBuilderDecorator() {
        public AsyncHttpClient.BoundRequestBuilder decorate(AsyncHttpClient.BoundRequestBuilder builder) {
            return builder.setFollowRedirects(true);
        }
    };

    private static final AsyncCompletionHandler<Boolean> DEFAULT_HANDLER = new AsyncCompletionHandler<Boolean>() {
        @Override
        public Boolean onCompleted(Response response) throws Exception {
            return response.getStatusCode() == 200;
        }
    };

    @Test
    public void testLogin() {

        TestBody.test(new HttpServerTestBody() {
                    @Override
                    protected void execute() throws Exception {
                        setServlet(new AdminServlet());
                        KeyPair keyPair = KeyTestUtil.getKeyPairFromProperties("b2048", "id_rsa");

                        DefaultKeychain provider = new DefaultKeychain();
                        provider.add(new JCEKey(KeyFormat.SSH_RSA, keyPair));

                        Signer signer = new Signer(provider);

                        // TODO find out why connection pooling breaks the last request
                        AsyncHttpClient client = new AsyncHttpClient(new AsyncHttpClientConfig.Builder().setAllowPoolingConnection(false).build());

                        assertTrue("login should be successful", AsyncUtil.login(
                                String.format("http://localhost:%d/index.html", getPort()),
                                signer, "admin", client, true, 1000, DEFAULT_HANDLER, null
                        ));
                    }
                }
        );

    }
}
