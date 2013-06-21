package net.adamcin.sshkey.clientauth.async;

import com.ning.http.client.AsyncCompletionHandler;
import com.ning.http.client.AsyncCompletionHandlerBase;
import com.ning.http.client.AsyncHandler;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.ListenableFuture;
import com.ning.http.client.Request;
import com.ning.http.client.Response;
import com.ning.http.util.AsyncHttpProviderUtils;
import net.adamcin.sshkey.commons.Authorization;
import net.adamcin.sshkey.commons.Challenge;
import net.adamcin.sshkey.commons.Constants;
import net.adamcin.sshkey.commons.Signer;

import java.net.URL;

public final class LoginChallengeHandler <T> extends AsyncCompletionHandler<T> {
    private static final RequestBuilderDecorator DEFAULT_REQUEST_DECORATOR = new RequestBuilderDecorator() {
        public AsyncHttpClient.BoundRequestBuilder decorate(AsyncHttpClient.BoundRequestBuilder builder) {
            return builder;
        }
    };

    private final Signer signer;
    private final AsyncHttpClient client;
    private final Request request;
    private final AsyncCompletionHandler<T> delegatee;
    private final RequestBuilderDecorator decorator;

    public LoginChallengeHandler(Signer signer, AsyncHttpClient client,
                                 Request request, AsyncCompletionHandler<T> delegatee,
                                 RequestBuilderDecorator decorator) {
        this.signer = signer;
        this.client = client;
        this.request = request;
        this.delegatee = delegatee;
        if (decorator == null) {
            this.decorator = DEFAULT_REQUEST_DECORATOR;
        } else {
            this.decorator = decorator;
        }
    }

    private static String getLoginUrl(Request request) {
        if (request.isUseRawUrl()) {
            return request.getRawUrl();
        } else {
            return request.getUrl();
        }
    }

    private static String getHost(Request request) {
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

    private static String getUserAgent(AsyncHttpClient client, Request request) {
        if (request.getHeaders().getFirstValue(Constants.HEADER_USER_AGENT) != null) {
            return request.getHeaders().getFirstValue(Constants.HEADER_USER_AGENT);
        } else if (client.getConfig().getUserAgent() != null) {
            return client.getConfig().getUserAgent();
        } else {
            return AsyncHttpProviderUtils.constructUserAgent(client.getProvider().getClass());
        }
    }

    @Override
    public T onCompleted(Response response) throws Exception {
        if (response.getStatusCode() == 401) {
            Challenge challenge = Challenge.parseChallenge(
                    response.getHeader(Constants.HEADER_CHALLENGE),
                    getHost(request),
                    getUserAgent(client, request)
            );

            if (challenge != null) {
                Authorization authorization = signer.sign(challenge);
                if (authorization != null) {
                    Request authRequest = decorator.decorate(client.prepareGet(getLoginUrl(request))).addHeader(
                            Constants.HEADER_AUTHORIZATION,
                            authorization.toString()
                    ).build();

                    ListenableFuture<T> authFuture = client.executeRequest(authRequest, delegatee);

                    return authFuture.get();
                } else {
                    throw new Exception("Signing identity not found");
                }
            } else {
                throw new Exception("SSHKey login not available");
            }

        } else {
            return delegatee.onCompleted(response);
        }
    }
}
