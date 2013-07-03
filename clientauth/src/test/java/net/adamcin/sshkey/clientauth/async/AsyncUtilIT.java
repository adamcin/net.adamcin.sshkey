package net.adamcin.sshkey.clientauth.async;

import com.ning.http.client.AsyncCompletionHandler;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.Response;
import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.sshkey.clientauth.KeyTestUtil;
import net.adamcin.sshkey.api.Signer;
import net.adamcin.sshkey.api.SignerFactory;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.*;

public class AsyncUtilIT {

    private static final RequestBuilderDecorator FOLLOW_REDIRECTS_DECORATOR = new RequestBuilderDecorator() {
        public AsyncHttpClient.BoundRequestBuilder decorate(AsyncHttpClient.BoundRequestBuilder builder) {
            return builder.setFollowRedirects(true);
        }
    };

    @Test
    public void testLogin() {

        TestBody.test(new TestBody() {
            @Override
            protected void execute() throws Exception {

                Signer signer = SignerFactory.getFactoryInstance().getInstance();

                File keyFile = KeyTestUtil.getPrivateKeyAsFile("b2048", "id_rsa");

                signer.addLocalKey(keyFile.getPath(), null);

                AsyncHttpClient client = new AsyncHttpClient();

                assertTrue("logged in", AsyncUtil.login("http://localhost:4502/index.html", signer, "admin", client, true, 60000, new AsyncCompletionHandler<Boolean>() {
                    @Override
                    public Boolean onCompleted(Response response) throws Exception {
                        return response.getStatusCode() == 200;
                    }
                }, FOLLOW_REDIRECTS_DECORATOR));

            }
        });

    }
}
