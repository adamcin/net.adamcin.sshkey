package net.adamcin.sshkey.clientauth.async;

import com.ning.http.client.AsyncCompletionHandlerBase;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.ListenableFuture;
import com.ning.http.client.Request;
import com.ning.http.client.Response;
import com.ning.http.util.AsyncHttpProviderUtils;
import net.adamcin.sshkey.commons.Authorization;
import net.adamcin.sshkey.commons.Challenge;
import net.adamcin.sshkey.commons.Constants;
import net.adamcin.sshkey.commons.Signer;

import java.io.IOException;
import java.net.URL;
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

    public static String getHost(Request request) {
        try {
            URL url = new URL(request.getRawUrl());
            String host = url.getHost();
            if (url.getPort() >= 0 && url.getPort() != url.getDefaultPort()) {
                return host + ":" + url.getPort();
            } else {
                return host;
            }
        } catch (Exception e) {
            return "";
        }
    }

    public static String getUserAgent(AsyncHttpClient client, Request request) {
        if (request.getHeaders().getFirstValue(Constants.HEADER_USER_AGENT) != null) {
            return request.getHeaders().getFirstValue(Constants.HEADER_USER_AGENT);
        } else if (client.getConfig().getUserAgent() != null) {
            return client.getConfig().getUserAgent();
        } else {
            return AsyncHttpProviderUtils.constructUserAgent(client.getProvider().getClass());
        }
    }

    public static boolean login(final String loginUri, final Signer signer, final String username, final int expectStatus,
                                final AsyncHttpClient client, final boolean checkTimeout, final long timeoutRemaining)
            throws IOException {

        final long timeoutAt = System.currentTimeMillis() + timeoutRemaining;
        final AsyncHttpClient.BoundRequestBuilder requestBuilder = client.prepareGet(loginUri).setUrl(loginUri);

        setHeaders(requestBuilder, signer, username);
        final Request request = requestBuilder.build();


        ListenableFuture<Response> future = client.executeRequest(request, new AsyncCompletionHandlerBase() {

            @Override
            public Response onCompleted(Response response) throws Exception {
                if (response.getStatusCode() == 401) {
                    Challenge challenge = Challenge.parseChallenge(
                            response.getHeader(Constants.HEADER_CHALLENGE),
                            getHost(request),
                            getUserAgent(client, request)
                    );

                    if (challenge != null) {
                        Authorization authorization = signer.sign(challenge);
                        if (authorization != null) {
                            Request authRequest = client.prepareGet(loginUri).setFollowRedirects(true).addHeader(
                                    Constants.HEADER_AUTHORIZATION,
                                    authorization.toString()
                            ).build();


                            ListenableFuture<Response> authFuture =
                                    client.executeRequest(authRequest,
                                                          new AsyncCompletionHandlerBase());

                            if (checkTimeout) {
                                return authFuture.get(timeoutAt - System.currentTimeMillis(), TimeUnit.MILLISECONDS);
                            } else {
                                return authFuture.get();
                            }
                        }
                    }
                }

                return response;
            }
        });

        try {
            if (checkTimeout) {
                return future.get(timeoutRemaining, TimeUnit.MILLISECONDS).getStatusCode() == expectStatus;
            } else {
                return future.get().getStatusCode() == expectStatus;
            }
        } catch (TimeoutException e) {
            throw new IOException("timeout exceeded");
        } catch (Exception e) {
            throw new IOException("failed to execute login request", e);
        }
    }
}
