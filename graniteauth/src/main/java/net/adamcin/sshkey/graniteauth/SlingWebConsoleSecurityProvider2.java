package net.adamcin.sshkey.graniteauth;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.apache.felix.webconsole.WebConsoleSecurityProvider2;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.auth.core.AuthenticationSupport;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

@Component(label = "Enhanced Sling Web Console Security Provider", metatype = true)
@Service
public class SlingWebConsoleSecurityProvider2 implements WebConsoleSecurityProvider2 {
    private static final Logger LOGGER = LoggerFactory.getLogger(SlingWebConsoleSecurityProvider2.class);

    @Property(name = "service.ranking")
    private static final int SERVICE_RANKING = 1000;

    @Property(value = "admin", cardinality = 20)
    private static final String OSGI_USERS = "users";

    @Property(value = "administrators", cardinality = 20)
    private static final String OSGI_GROUPS = "groups";

    @Reference
    private AuthenticationSupport authSupport;

    private Set<String> users;
    private Set<String> groups;

    @Activate
    protected void activate(ComponentContext ctx, Map<String, Object> config) {
        this.users = toSet(config.get(OSGI_USERS));
        this.groups = toSet(config.get(OSGI_GROUPS));
    }

    public boolean authenticate(HttpServletRequest request, HttpServletResponse response) {
        if (authSupport.handleSecurity(request, response)) {
            try {
                ResourceResolver resolver = (ResourceResolver) request.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER);
                if (resolver != null) {
                    User user = resolver.adaptTo(User.class);
                    if (user != null) {
                        if (this.users.contains(user.getID())) {
                            return true;
                        }

                        Iterator<Group> memberOf = user.memberOf();
                        if (memberOf != null) {
                            while (memberOf.hasNext()) {
                                Group group = memberOf.next();
                                if (groups.contains(group.getID())) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            } catch (RepositoryException e) {
                LOGGER.error("[authenticate] failed to check identity of Sling request");
            }
        }
        return false;
    }

    public Object authenticate(String username, String password) {
        return null;
    }

    private Set<String> toSet(Object configObj) {
        Set<String> groups = new HashSet<String>();
        if (configObj instanceof String) {
            groups.add((String) configObj);
        } else {
            if (configObj instanceof Collection) {
                for (Object obj : (Collection) configObj) {
                    if (obj instanceof String) {
                        groups.add((String) obj);
                    }
                }
            } else if (configObj instanceof String[]) {
                for (String string : (String[]) configObj) {
                    if (string != null) {
                        groups.add(string);
                    }
                }
            }
        }
        return groups;
    }

    public boolean authorize(Object o, String s) {
        return true;
    }
}
