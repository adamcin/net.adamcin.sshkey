package net.adamcin.sshkey.provider.jsch;

import net.adamcin.sshkey.api.Signer;
import net.adamcin.sshkey.api.SignerFactory;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Service;

@Component
@Service(SignerFactory.class)
@Properties({
    @Property(name = "service.ranking", intValue = -1)
})
public class JschSignerFactory extends SignerFactory {

    public Signer getInstance() {
        return new JschSigner();
    }
}
