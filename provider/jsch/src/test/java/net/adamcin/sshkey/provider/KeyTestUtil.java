package net.adamcin.sshkey.provider;

import net.adamcin.commons.testing.junit.FailUtil;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 *
 */
public class KeyTestUtil {

    private static final File TEST_TEMP = new File("target/test-temp");
    static {
        TEST_TEMP.mkdirs();
    }

    public InputStream getAuthorizedKeysStream() {
        return getClass().getResourceAsStream("/authorized_keys");
    }

    public static File getAuthorizedKeysFile() {
        return getResourceAsFile("/authorized_keys");
    }

    public static File getPrivateKeyAsFile(String parentName, String keyName) {
        return getResourceAsFile("/" + parentName + "/" + keyName);
    }

    public static File getPublicKeyAsFile(String parentName, String keyName) {
        return getResourceAsFile("/" + parentName + "/" + keyName + ".pub");
    }

    private static File getResourceAsFile(String name) {
        InputStream is = null;
        OutputStream os = null;
        try {
            is = KeyTestUtil.class.getResourceAsStream(name);
            File temp = File.createTempFile("sshkeytest", ".tmp", TEST_TEMP);
            os = new FileOutputStream(temp);
            IOUtils.copy(is, os);
            return temp;
        } catch (IOException e) {
            FailUtil.sprintFail(e);
        } finally {
            IOUtils.closeQuietly(is);
            IOUtils.closeQuietly(os);
        }
        return null;
    }
}
