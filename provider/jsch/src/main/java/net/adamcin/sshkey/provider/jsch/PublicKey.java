package net.adamcin.sshkey.provider.jsch;

import com.jcraft.jsch.HASH;
import com.jcraft.jsch.Signature;
import com.jcraft.jsch.jce.MD5;
import net.adamcin.sshkey.api.Authorization;
import net.adamcin.sshkey.api.Base64;
import net.adamcin.sshkey.api.Challenge;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

abstract class PublicKey {
    private static final Pattern KEY_PATTERN = Pattern.compile("^([^\\s]+)\\s+([^\\s]+)(\\s|$)");
    private static final int GROUP_FORMAT = 1;
    private static final int GROUP_KEY = 2;
    private static final String[] fingerPrintChars = {
            "0","1","2","3","4","5","6","7","8","9", "a","b","c","d","e","f"
    };

    protected final String format;
    protected final String encodedKey;
    protected final byte[] key;

    protected PublicKey(String format, String encodedKey) {
        this.format = format;
        this.encodedKey = encodedKey;
        this.key = Base64.fromBase64(encodedKey.getBytes());
    }

    /**
     * Essentially copied from {@link com.jcraft.jsch.Util#getFingerPrint(com.jcraft.jsch.HASH, byte[])}
     * @param keyBlob
     * @return
     */
    public static String getKeyFingerprint(byte[] keyBlob) throws Exception {
        HASH hash = new MD5();
        hash.init();
        hash.update(keyBlob, 0, keyBlob.length);
        byte[] foo = hash.digest();
        StringBuffer sb = new StringBuffer();
        int bar;
        for(int i = 0; i < foo.length; i++){
            bar = foo[i]&0xff;
            sb.append(fingerPrintChars[(bar>>>4)&0xf]);
            sb.append(fingerPrintChars[(bar)&0xf]);
            if(i + 1 < foo.length) {
                sb.append(":");
            }
        }
        return sb.toString();
    }

    public boolean verify(Challenge challenge, Authorization packet) throws Exception {
        if (packet != null) {
            Signature sig = this.getSignature();
            sig.update(challenge.getHash());
            return sig.verify(packet.getSignatureBytes());
        }
        return false;
    }

    abstract Signature getSignature() throws Exception;

    @Override
    public abstract boolean equals(Object obj);

    @Override
    public abstract int hashCode();

    @Override
    public String toString() {
        return format + " " + encodedKey;
    }

    public String getFingerprint() {
        try {
            return getKeyFingerprint(key);
        } catch (Exception e) {
        }
        return null;
    }

    public static List<PublicKey> readKeys(Reader reader) throws IOException {

        List<PublicKey> keys = new ArrayList<PublicKey>();
        BufferedReader bufferedReader = new BufferedReader(reader);

        String line;
        while ((line = bufferedReader.readLine()) != null) {
            PublicKey key = readKey(line);
            if (key != null) {
                keys.add(key);
            }
        }

        return Collections.unmodifiableList(keys);
    }

    public static PublicKey readKey(String publicKeyString) {
        if (publicKeyString != null) {
            Matcher matcher = KEY_PATTERN.matcher(publicKeyString);
            if (matcher.find()) {
                String format = matcher.group(GROUP_FORMAT);
                String key = matcher.group(GROUP_KEY);
                return createKey(format, key);
            }
        }
        return null;
    }

    public static PublicKey createKey(String format, String encodedKey) {
        if (PublicKeyDSA.FORMAT.equals(format)) {
            return new PublicKeyDSA(format, encodedKey);
        } else if (PublicKeyRSA.FORMAT.equals(format)) {
            return new PublicKeyRSA(format, encodedKey);
        }

        return null;
    }
}
