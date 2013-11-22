package net.adamcin.sshkey.simple;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Implementation of SSH Protocol Public Key formats
 */
public final class RFCUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(RFCUtil.class);

    private static final char[] fingerPrintChars = {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };


    /**
     * Computes the MD5 fingerprint of the public key blob
     *
     * @param keyBlob base64-decoded byte array containing the public key spec
     * @return
     * @see <a href="http://tools.ietf.org/html/rfc4716#section-4">[RFC4716] Section 4: Public Key Fingerprints</a>
     */
    public static String getFingerprint(byte[] keyBlob) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("MD5");
            byte[] foo = digest.digest(keyBlob);

            StringBuilder sb = new StringBuilder();
            int bar;
            for (int i = 0; i < foo.length; i++) {
                bar = foo[i] & 0xff;
                sb.append(fingerPrintChars[(bar >>> 4) & 0xf]);
                sb.append(fingerPrintChars[(bar) & 0xf]);
                if (i + 1 < foo.length) {
                    sb.append(":");
                }
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // should not happen in a standard JVM
            e.printStackTrace(System.err);
        }

        return null;
    }

}
