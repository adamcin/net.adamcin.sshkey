package net.adamcin.sshkey.api;

import org.junit.Test;

import static org.junit.Assert.*;
import static org.apache.commons.codec.binary.Base64.encodeBase64;
import static org.apache.commons.codec.binary.Base64.decodeBase64;


public class Base64Test {

    @Test
    public void testTo() {

        byte[] foobarBytes = "foobar".getBytes();
        assertEquals(
                "foobar should be encoded the same way as in commons-codec",
                new String(encodeBase64(foobarBytes, false), Constants.CHARSET),
                Base64.toBase64String(foobarBytes)
        );
    }

    @Test
    public void testFrom() {
        byte[] foobarBytes = "foobar".getBytes();
        String encoded = new String(encodeBase64(foobarBytes, false), Constants.CHARSET);

        assertEquals("foobar (encoded) should be decoded the same way as in commons-codec",
                     new String(decodeBase64(encoded.getBytes(Constants.CHARSET))),
                     new String(Base64.fromBase64String(encoded)));
    }
}
