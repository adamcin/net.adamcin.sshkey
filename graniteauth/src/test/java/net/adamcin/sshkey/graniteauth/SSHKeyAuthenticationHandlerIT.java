package net.adamcin.sshkey.graniteauth;


import net.adamcin.commons.testing.junit.FailUtil;
import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.commons.testing.sling.SlingITContext;
import net.adamcin.commons.testing.sling.VltpackITContext;
import net.adamcin.sshkey.clientauth.http4.SSHKeyAuthScheme;
import net.adamcin.sshkey.commons.Constants;
import net.adamcin.sshkey.commons.Signer;
import net.adamcin.sshkey.commons.SignerException;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthSchemeFactory;
import org.apache.http.auth.params.AuthPNames;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.HttpParams;
import org.apache.sling.testing.tools.http.Request;
import org.apache.sling.testing.tools.http.RequestCustomizer;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Arrays;

public class SSHKeyAuthenticationHandlerIT {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSHKeyAuthenticationHandlerIT.class);
    private SlingITContext context = new VltpackITContext();

    @Test
    public void testFail() {
        TestBody.test(new TestBody() {
            @Override protected void execute() throws Exception {

                final Signer signer = new Signer();

                File pkeyFile = SSHKeyTestUtil.getPrivateKeyAsFile("withpass");
                try {
                    signer.addLocalKey(pkeyFile.getAbsolutePath(), "dummydummy");
                } catch (SignerException e) {
                    FailUtil.sprintFail(e);
                }

                DefaultHttpClient client = (DefaultHttpClient) context.getHttpClient();
                client.getAuthSchemes().register("SSHKey", new AuthSchemeFactory() {
                    public AuthScheme newInstance(HttpParams params) {
                        LOGGER.error("[newInstance]");
                        return new SSHKeyAuthScheme(signer, params);
                    }
                });

                client.getParams().setParameter(AuthPNames.TARGET_AUTH_PREF, Arrays.asList("sshkey"));
                HttpClientParams.setAuthenticating(client.getParams(), true);
                RequestCustomizer customizer = new RequestCustomizer() {

                    public void customizeRequest(Request r) {
                        r.getRequest().setHeader(Constants.HEADER_X_SSHKEY_USERNAME, "admin");
                        for (String fingerprint : signer.getFingerprints()) {
                            r.getRequest().addHeader(Constants.HEADER_X_SSHKEY_FINGERPRINT, fingerprint);
                        }
                    }
                };

                Request request = context.getRequestBuilder().buildGetRequest("/index.html").withCustomizer(customizer);

                HttpResponse response = context.getRequestExecutor().execute(request).assertStatus(200).getResponse();
            }
        });

    }
}
