package net.adamcin.sshkey.clientauth.http3;

import net.adamcin.sshkey.commons.Constants;
import net.adamcin.sshkey.commons.Signer;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.auth.AuthPolicy;
import org.apache.commons.httpclient.auth.CredentialsProvider;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.params.DefaultHttpParams;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public final class Http3Util {

    public static void enableAuth(Signer signer, HttpClient client) {
        CredentialsProvider credProvider =
            (CredentialsProvider) client.getParams()
                    .getParameter(CredentialsProvider.PROVIDER);

        CredentialsProvider newProvider;
        if (credProvider instanceof SignerCredentialsProvider) {
            newProvider = new SignerCredentialsProvider(signer,
                                                        ((SignerCredentialsProvider) credProvider).getDelegatee());
        } else {
            newProvider = new SignerCredentialsProvider(signer, credProvider);
        }

        client.getParams().setParameter(CredentialsProvider.PROVIDER, newProvider);
        AuthPolicy.registerAuthScheme(Constants.SCHEME, Http3SSHKeyAuthScheme.class);
        List<String> schemes = new ArrayList<String>();
        schemes.add(Constants.SCHEME);
        schemes.addAll((Collection) DefaultHttpParams.getDefaultParams().getParameter(AuthPolicy.AUTH_SCHEME_PRIORITY));
        client.getParams().setParameter(AuthPolicy.AUTH_SCHEME_PRIORITY, schemes);
    }

    public static void setHeaders(HttpMethod method, String username, Signer signer) {
        if (method != null) {
            if (username != null) {
                method.setRequestHeader(Constants.HEADER_X_SSHKEY_USERNAME, username);
            } else {
                method.removeRequestHeader(Constants.HEADER_X_SSHKEY_USERNAME);
            }
            while (method.getRequestHeader(Constants.HEADER_X_SSHKEY_FINGERPRINT) != null) {
                method.removeRequestHeader(Constants.HEADER_X_SSHKEY_FINGERPRINT);
            }
            if (signer != null) {
                for (String fingerprint : signer.getFingerprints()) {
                    method.addRequestHeader(Constants.HEADER_X_SSHKEY_FINGERPRINT, fingerprint);
                }
            }
        }
    }

    public static boolean login(String loginUri, Signer signer, String username, int expectStatus,
                                HttpClient client)
            throws IOException {

        enableAuth(signer, client);
        GetMethod method = new GetMethod(loginUri);
        setHeaders(method, username, signer);
        return expectStatus == client.executeMethod(method);
    }


    private Http3Util() {
    }
}
