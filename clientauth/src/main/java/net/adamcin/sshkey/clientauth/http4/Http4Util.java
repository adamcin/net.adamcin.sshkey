package net.adamcin.sshkey.clientauth.http4;

import net.adamcin.sshkey.commons.Constants;
import net.adamcin.sshkey.commons.Signer;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthSchemeFactory;
import org.apache.http.auth.params.AuthPNames;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.params.HttpParams;

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
                return new Http4SSHKeyAuthScheme(signer, params);
            }
        });

        client.getParams().setParameter(AuthPNames.TARGET_AUTH_PREF,
                                        Arrays.asList(Constants.SCHEME));

        HttpClientParams.setAuthenticating(client.getParams(), true);
    }

    public static void setHeaders(HttpUriRequest request, String username, Signer signer) {
        if (request != null) {

            request.removeHeaders(Constants.HEADER_X_SSHKEY_USERNAME);
            if (username != null) {
                request.setHeader(Constants.HEADER_X_SSHKEY_USERNAME, username);
            }

            request.removeHeaders(Constants.HEADER_X_SSHKEY_FINGERPRINT);
            if (signer != null) {
                for (String fingerprint : signer.getFingerprints()) {
                    request.addHeader(Constants.HEADER_X_SSHKEY_FINGERPRINT, fingerprint);
                }
            }
        }
    }

    private Http4Util() {
    }

}
