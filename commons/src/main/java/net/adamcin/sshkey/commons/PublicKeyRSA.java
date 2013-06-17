package net.adamcin.sshkey.commons;

import com.jcraft.jsch.Buffer;
import com.jcraft.jsch.Signature;
import com.jcraft.jsch.jce.SignatureRSA;

import java.util.Arrays;

final class PublicKeyRSA extends PublicKey {

    public static final String FORMAT = "ssh-rsa";

    public PublicKeyRSA(String format, String encodedKey) {
        super(format, encodedKey);
    }

    @Override
    public Signature getSignature() throws Exception {
        SignatureRSA signature = new SignatureRSA();

        Buffer buf = new Buffer(this.key);

        signature.init();
        buf.getString(); // read the format string first
        byte[] e = buf.getString();
        byte[] n = buf.getString();
        signature.setPubKey(e, n);
        return signature;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof PublicKeyRSA)) {
            return false;
        }

        PublicKeyRSA otherKey = (PublicKeyRSA) obj;

        return Arrays.equals(this.key, otherKey.key);
    }

    @Override
    public int hashCode() {
        return FORMAT.hashCode() + Arrays.hashCode(this.key);
    }
}
