package net.adamcin.sshkey.simple;

import net.adamcin.sshkey.api.Base64;
import net.adamcin.sshkey.api.Identity;
import net.adamcin.sshkey.api.Verifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
