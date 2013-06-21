package net.adamcin.sshkey.clientauth.async;

import com.ning.http.client.AsyncHttpClient;


public interface RequestBuilderDecorator {

    AsyncHttpClient.BoundRequestBuilder decorate(AsyncHttpClient.BoundRequestBuilder builder);
}
