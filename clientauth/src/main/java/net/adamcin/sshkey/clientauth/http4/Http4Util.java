package net.adamcin.sshkey.clientauth.http4;

import net.adamcin.sshkey.api.Constants;
import net.adamcin.sshkey.api.Signer;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthSchemeFactory;
import org.apache.http.auth.params.AuthPNames;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;

import java.io.IOException;
import java.util.Arrays;

public final class Http4Util {

    public static void enableAuth(final Signer signer, AbstractHttpClient client) {
        if (signer == null) {
            throw new NullPointerException("signer");
        }

        if (client == null) {
            throw new NullPointerException("client");
        }

        client.getAuthSchemes().register(Constants.SCHEME, new AuthSchemeFactory() {
            public AuthScheme newInstance(HttpParams params) {
                return new Http4SSHKeyAuthScheme(signer);
            }
        });

        client.getParams().setParameter(AuthPNames.TARGET_AUTH_PREF,
                                        Arrays.asList(Constants.SCHEME));

        HttpClientParams.setAuthenticating(client.getParams(), true);
    }

    public static void setHeaders(HttpUriRequest request, Signer signer, String username) {
        if (request != null) {

            request.removeHeaders(Constants.SSHKEY_USERNAME);
            if (username != null) {
                request.setHeader(Constants.SSHKEY_USERNAME, username);
            }

            request.removeHeaders(Constants.SSHKEY_FINGERPRINT);
            if (signer != null) {
                for (String fingerprint : signer.getFingerprints()) {
                    request.addHeader(Constants.SSHKEY_FINGERPRINT, fingerprint);
                }
            }
        }
    }

    public static boolean login(String loginUri, Signer signer, String username, int expectStatus,
                                AbstractHttpClient client,
                                HttpContext context)
            throws IOException {

        enableAuth(signer, client);
        HttpUriRequest request = new HttpGet(loginUri);
        setHeaders(request, signer, username);
        return client.execute(request, context).getStatusLine().getStatusCode() == expectStatus;
    }

    private Http4Util() {
    }

}
