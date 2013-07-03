package net.adamcin.sshkey.graniteauth;

import com.adobe.granite.crypto.CryptoException;
import com.adobe.granite.crypto.CryptoSupport;
import com.day.crx.security.token.TokenCookie;
import com.day.crx.security.token.TokenUtil;
import net.adamcin.sshkey.api.Authorization;
import net.adamcin.sshkey.api.Constants;
import net.adamcin.sshkey.api.Verifier;
import net.adamcin.sshkey.api.VerifierException;
import net.adamcin.sshkey.api.VerifierFactory;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.apache.sling.auth.core.spi.AbstractAuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.commons.osgi.PropertiesUtil;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.settings.SlingSettingsService;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component(label = "SSH Key Authentication Handler", metatype = true)
@Service
public final class SSHKeyAuthenticationHandler extends AbstractAuthenticationHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSHKeyAuthenticationHandler.class);

    private static final String AUTHORIZED_KEYS_REL_PATH = ".ssh/authorized_keys";
    private static final int MAX_SESSIONS = 10000;

    @Property(name = TYPE_PROPERTY, propertyPrivate = true)
    private static final String AUTH_TYPE = "SSHKey";

    @Property(name = PATH_PROPERTY, label = "Path")
    private static final String AUTH_PATH = "/";

    @Property(name = "service.ranking", label = "Service Ranking")
    private static final String SERVICE_RANKING = "10000";

    @Property(label = "Authorized Keys File", description = "Path to authorized_keys file. Leave empty to expect ${sling.home}../.ssh/authorized_keys or ${user.home}/.ssh/authorized_keys.", value = "")
    private static final String OSGI_AUTH_KEYS_PATH = "auth.sshkey.authorized_keys";

    private static final String DEFAULT_REALM = "Day Communique 5";
    @Property(label = "Realm", description = "Authentication Realm", value = DEFAULT_REALM)
    private static final String OSGI_REALM = "auth.sshkey.realm";

    @Property(label = "Disabled", description = "Check to disable sshkey authentication", boolValue = false)
    private static final String OSGI_DISABLED = "auth.sshkey.disabled";

    @Reference
    private SlingSettingsService slingSettingsService;

    @Reference
    private SlingRepository repository;

    @Reference
    private CryptoSupport cryptoSupport;

    @Reference(cardinality = ReferenceCardinality.OPTIONAL_UNARY)
    private VerifierFactory verifierFactory;

    private final VerifierFactory defaultVerifierFactory = VerifierFactory.getFactoryInstance();

    private boolean disabled;
    private String authorizedKeysPath;
    private String realm;

    private final Map<String, SSHKeySession> sessions = Collections.synchronizedMap(new HashMap<String, SSHKeySession>());

    @Activate
    protected void activate(ComponentContext ctx, Map<String, Object> props) {
        this.disabled = PropertiesUtil.toBoolean(props.get(OSGI_DISABLED), false);
        this.authorizedKeysPath = PropertiesUtil.toString(props.get(OSGI_AUTH_KEYS_PATH), "");
        this.realm = PropertiesUtil.toString(props.get(OSGI_REALM), DEFAULT_REALM);
    }

    private VerifierFactory getVerifierFactory() {
        if (verifierFactory != null) {
            return verifierFactory;
        } else {
            return defaultVerifierFactory;
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctx) {
        this.disabled = false;
        this.authorizedKeysPath = null;
        this.realm = null;

        synchronized (sessions) {
            sessions.clear();
        }
    }

    protected boolean isAllowedToLogin(HttpServletRequest request) {
        return true;
    }

    protected Verifier getVerifier() {
        Verifier verifier = getVerifierFactory().getInstance();
        try {
            verifier.readAuthorizedKeys(getAuthorizedKeysFile());
        } catch (VerifierException e) {
            LOGGER.error("[activate] Failed to read authorized_keys file", e);
        }
        return verifier;
    }

    protected File getAuthorizedKeysFile() {
        if (authorizedKeysPath != null && authorizedKeysPath.trim().length() > 0) {
            File configOverride = new File(authorizedKeysPath);
            if (configOverride.exists() && configOverride.canRead()) {
                return configOverride;
            } else {
                return null;
            }
        }

        File appOverride = new File(slingSettingsService.getSlingHomePath(),
                                    ".." + File.separator + AUTHORIZED_KEYS_REL_PATH);

        if (appOverride.exists() && appOverride.canRead()) {
            return appOverride;
        } else {
            File userFile = new File(System.getProperty("user.home"), AUTHORIZED_KEYS_REL_PATH);
            if (userFile.exists() && userFile.canRead()) {
                return userFile;
            } else {
                return null;
            }
        }
    }

    /**
     *
     * @param request
     * @param response
     * @return
     */
    public AuthenticationInfo extractCredentials(HttpServletRequest request,
                                                 HttpServletResponse response) {

        if (isDisabled() || !isAllowedToLogin(request) ) {
            return null;
        }

        AuthenticationInfo info = handleLogin(request, response);
        if (info != null) {
            return info;
        }

        if (forceAuthentication(request, response)) {
            return AuthenticationInfo.DOING_AUTH;
        }

        return null;
    }

    protected static String getSSHKeyUsername(HttpServletRequest request) {
        return request.getHeader(Constants.SSHKEY_USERNAME);
    }

    protected boolean forceAuthentication(HttpServletRequest request,
                                          HttpServletResponse response) {

        return sendChallenge(request, response);
    }

    protected String selectFingerprint(String username, HttpServletRequest request) {
        List<String> _fingerprints = new ArrayList<String>();
        Enumeration fingerprints = request.getHeaders(Constants.SSHKEY_FINGERPRINT);
        if (fingerprints != null) {
            while (fingerprints.hasMoreElements()) {
                String fingerprint = (String) fingerprints.nextElement();
                _fingerprints.add(fingerprint);
            }
        }
        return getVerifier().selectFingerprint(_fingerprints);
    }

    protected boolean sendChallenge(HttpServletRequest request,
                                    HttpServletResponse response) {
        if (response.isCommitted()) {
            return false;
        }

        String username = getSSHKeyUsername(request);
        if (username == null) {
            return false;
        }

        String fingerprint = selectFingerprint(username, request);
        if (fingerprint == null) {
            return false;
        }

        SSHKeySession session = createSession(username, fingerprint, request);

        if (session != null) {
            response.reset();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setHeader(Constants.CHALLENGE, session.getChallenge().toString());

            try {
                response.flushBuffer();
                return true;
            } catch (IOException e) {
                LOGGER.error("[sendChallenge] Failed to send challenge", e);
            }
        }

        return false;
    }

    protected SSHKeySession createSession(String username, String fingerprint, HttpServletRequest request) {
        if (sessions.size() < MAX_SESSIONS) {
            try {
                SSHKeySession session = SSHKeySession.createSession(cryptoSupport, username, fingerprint, realm, request);
                synchronized (this.sessions) {
                    this.sessions.put(session.getChallenge().getNonce(), session);
                }
                return session;
            } catch (CryptoException e) {
                LOGGER.error("[createSession] failed to encrypt session");
            }
        }
        return null;
    }

    protected SSHKeySession validateSession(HttpServletRequest request, String token) {
        if (this.sessions.containsKey(token)) {
            synchronized (this.sessions) {
                SSHKeySession session = this.sessions.remove(token);
                if (session != null && session.validateRequest(request, 60L * 1000L)) {
                    return session;
                }
            }
        }

        return null;
    }

    public boolean requestCredentials(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        return !isDisabled() && isAllowedToLogin(request) && forceAuthentication(request, response);
    }

    public void dropCredentials(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        // do nothing
    }

    public boolean isDisabled() {
        return disabled;
    }

    public AuthenticationInfo handleLogin(HttpServletRequest request,
                                                 HttpServletResponse response) {

        // Return immediately if the header is missing
        String authHeader = request.getHeader(Constants.AUTHORIZATION);
        if (authHeader == null || authHeader.length() == 0) {
            return null;
        }

        Authorization authorization = Authorization.parse(authHeader);
        if (authorization == null) {
            return null;
        }

        AuthenticationInfo info = null;

        SSHKeySession session = validateSession(request, authorization.getToken());

        try {
            boolean signatureValid = session != null && getVerifier().verify(session.getChallenge(), authorization);
            if (signatureValid) {
                if (request.getAttribute(TokenCookie.class.getName()) != null) {
                    request.setAttribute(TokenCookie.class.getName(), null);
                }
                info = TokenUtil.createCredentials(request, response, repository, session.getUsername(), false);
            }
        } catch (VerifierException e) {
            LOGGER.error("[handleLogin] failed to verify authorization", e);
        } catch (RepositoryException e) {
            LOGGER.error("[handleLogin] failed to create token", e);
        }

        if (info == null) {
            info = AuthenticationInfo.FAIL_AUTH;
        }

        return info;
    }
}
