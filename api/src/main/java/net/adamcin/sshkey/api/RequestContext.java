package net.adamcin.sshkey.api;

import java.io.Serializable;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

/**
 * Object used to pass per-request context, such as Request Line and HTTP Headers in client/server
 * implementation-independent way
 */
public final class RequestContext implements Serializable {
    public static final DateFormat DATE_FORMAT = new SimpleDateFormat("EEE MMM d HH:mm:ss yyyy zzz");

    private final String requestLine;
    private final Map<String, String> headers = new HashMap<String, String>();

    public RequestContext() {
        this(null);
    }

    public RequestContext(String requestLine) {
        this.requestLine = requestLine == null ? "" : requestLine;
    }

    /**
     * Returns the
     * @param name
     * @return
     */
    public String getHeaderValue(String name) {
        return "";
    }
}
