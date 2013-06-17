package net.adamcin.sshkey.clientauth.async;

import com.ning.http.client.AsyncHttpClient;
import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.sshkey.clientauth.KeyTestUtil;
import net.adamcin.sshkey.commons.Signer;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.*;

public class AsyncUtilIT {


    @Test
    public void testLogin() {

        TestBody.test(new TestBody() {
            @Override
            protected void execute() throws Exception {

                Signer signer = new Signer();

                File keyFile = KeyTestUtil.getPrivateKeyAsFile("b2048", "id_rsa");

                signer.addLocalKey(keyFile.getPath(), null);

                AsyncHttpClient client = new AsyncHttpClient();

                assertTrue("logged in", AsyncUtil.login("http://localhost:4502/index.html", signer, "admin", 200, client, true, 60000));

            }
        });

    }
}
