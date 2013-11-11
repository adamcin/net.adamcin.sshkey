package net.adamcin.sshkey.provider.jsch;

import net.adamcin.sshkey.api.Verifier;
import net.adamcin.sshkey.api.VerifierFactory;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Service;

@Component
@Service(VerifierFactory.class)
@Properties({
    @Property(name = "service.ranking", intValue = -1)
})
public class JschVerifierFactory extends VerifierFactory {

    public Verifier getInstance() {
        return new JschVerifier();
    }
}
