package net.adamcin.sshkey.clientauth.async;

import com.ning.http.client.AsyncCompletionHandler;
import com.ning.http.client.AsyncCompletionHandlerBase;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.ListenableFuture;
import com.ning.http.client.Request;
import com.ning.http.client.Response;
import net.adamcin.sshkey.commons.Constants;
import net.adamcin.sshkey.commons.Signer;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public final class AsyncUtil {

    public static void setHeaders(AsyncHttpClient.BoundRequestBuilder builder, Signer signer, String username) {
        if (builder != null) {
            Map<String, Collection<String>> headers = new HashMap<String, Collection<String>>();
            headers.put(Constants.HEADER_X_SSHKEY_USERNAME, Arrays.asList(username));

            if (signer != null) {
                headers.put(Constants.HEADER_X_SSHKEY_FINGERPRINT, signer.getFingerprints());
            } else {
                headers.put(Constants.HEADER_X_SSHKEY_FINGERPRINT, Collections.<String>emptyList());
            }

            builder.setHeaders(headers);
        }
    }

    public static Response login(final String loginUri, final Signer signer, final String username,
                                final AsyncHttpClient client, final boolean checkTimeout, final long timeoutRemaining)
            throws IOException {

        return login(loginUri, signer, username, client, checkTimeout, timeoutRemaining, new AsyncCompletionHandlerBase(), null);
    }

    public static <T> T login(final String loginUri, final Signer signer, final String username,
                                final AsyncHttpClient client, final boolean checkTimeout, final long timeoutRemaining,
                                AsyncCompletionHandler<T> handler, RequestBuilderDecorator loginRequestDecorator)
            throws IOException {

        final AsyncHttpClient.BoundRequestBuilder requestBuilder = client.prepareGet(loginUri).setUrl(loginUri);

        setHeaders(requestBuilder, signer, username);
        final Request request = requestBuilder.build();

        ListenableFuture<T> future = client.executeRequest(request, new LoginChallengeHandler<T>(signer, client,
                                                                                                 request, handler,
                                                                                                 loginRequestDecorator));

        try {
            if (checkTimeout) {
                return future.get(timeoutRemaining, TimeUnit.MILLISECONDS);
            } else {
                return future.get();
            }
        } catch (TimeoutException e) {
            throw new IOException("timeout exceeded");
        } catch (Exception e) {
            throw new IOException("failed to execute login request", e);
        }
    }
}
