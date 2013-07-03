package net.adamcin.sshkey.graniteauth;


import net.adamcin.commons.testing.junit.FailUtil;
import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.commons.testing.sling.SlingITContext;
import net.adamcin.commons.testing.sling.VltpackITContext;
import net.adamcin.sshkey.clientauth.http4.Http4Util;
import net.adamcin.sshkey.api.Signer;
import net.adamcin.sshkey.api.SignerException;
import net.adamcin.sshkey.api.SignerFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.sling.testing.tools.http.Request;
import org.apache.sling.testing.tools.http.RequestBuilder;
import org.apache.sling.testing.tools.http.RequestCustomizer;
import org.apache.sling.testing.tools.http.RequestExecutor;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class SSHKeyAuthenticationHandlerIT {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSHKeyAuthenticationHandlerIT.class);
    private SlingITContext context = new VltpackITContext();

    @Test
    public void testFail() {
        TestBody.test(new TestBody() {
            @Override protected void execute() throws Exception {

                final Signer signer = SignerFactory.getFactoryInstance().getInstance();

                try {
                    File pkeyFile = SSHKeyTestUtil.getPrivateKeyAsFile("b4096");
                    signer.addLocalKey(pkeyFile.getAbsolutePath(), null);
                    DefaultHttpClient client = (DefaultHttpClient) context.getHttpClient();

                    Http4Util.enableAuth(signer, client);
                    RequestCustomizer customizer = new RequestCustomizer() {
                        public void customizeRequest(Request r) {
                            Http4Util.setHeaders(r.getRequest(), signer, "admin");
                        }
                    };

                    RequestBuilder br = context.getRequestBuilder();
                    RequestExecutor ex = context.getRequestExecutor();

                    for (int i = 0; i < 100; i++) {
                        ex.execute(br.buildGetRequest("/index.html")
                                .withCustomizer(customizer))
                                .assertStatus(200).getResponse();
                    }
                } catch (SignerException e) {
                    FailUtil.sprintFail(e);
                } finally {
                    signer.clear();
                }

            }
        });

    }
}
