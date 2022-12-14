package tests;

import cardTools.CardManager;
import cardTools.RunConfig;
import org.junit.Assert;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class AppletTest extends BaseTest {

    private static final byte[] RSA_PUB_KEY_EXP = {(byte)0x01, (byte)0x00, (byte)0x01};
    private static final byte[] RSA_PUB_PRIV_KEY_MOD = { (byte)0xbe, (byte)0xdf,
            (byte)0xd3, (byte)0x7a, (byte)0x08, (byte)0xe2, (byte)0x9a, (byte)0x58,
            (byte)0x27, (byte)0x54, (byte)0x2a, (byte)0x49, (byte)0x18, (byte)0xce,
            (byte)0xe4, (byte)0x1a, (byte)0x60, (byte)0xdc, (byte)0x62, (byte)0x75,
            (byte)0xbd, (byte)0xb0, (byte)0x8d, (byte)0x15, (byte)0xa3, (byte)0x65,
            (byte)0xe6, (byte)0x7b, (byte)0xa9, (byte)0xdc, (byte)0x09, (byte)0x11,
            (byte)0x5f, (byte)0x9f, (byte)0xbf, (byte)0x29, (byte)0xe6, (byte)0xc2,
            (byte)0x82, (byte)0xc8, (byte)0x35, (byte)0x6b, (byte)0x0f, (byte)0x10,
            (byte)0x9b, (byte)0x19, (byte)0x62, (byte)0xfd, (byte)0xbd, (byte)0x96,
            (byte)0x49, (byte)0x21, (byte)0xe4, (byte)0x22, (byte)0x08, (byte)0x08,
            (byte)0x80, (byte)0x6c, (byte)0xd1, (byte)0xde, (byte)0xa6, (byte)0xd3,
            (byte)0xc3, (byte)0x8f};
    private static final byte[] RSA_PRIV_KEY_EXP = { (byte)0x84, (byte)0x21,
            (byte)0xfe, (byte)0x0b, (byte)0xa4, (byte)0xca, (byte)0xf9, (byte)0x7d,
            (byte)0xbc, (byte)0xfc, (byte)0x0e, (byte)0xa9, (byte)0xbb, (byte)0x7a,
            (byte)0xbd, (byte)0x7d, (byte)0x65, (byte)0x40, (byte)0x2b, (byte)0x08,
            (byte)0xc6, (byte)0xdf, (byte)0xc9, (byte)0x4b, (byte)0x09, (byte)0x6a,
            (byte)0x29, (byte)0x3b, (byte)0xc2, (byte)0x42, (byte)0x88, (byte)0x23,
            (byte)0x44, (byte)0xaf, (byte)0x08, (byte)0x82, (byte)0x4c, (byte)0xff,
            (byte)0x42, (byte)0xa4, (byte)0xb8, (byte)0xd2, (byte)0xda, (byte)0xcc,
            (byte)0xee, (byte)0xc5, (byte)0x34, (byte)0xed, (byte)0x71, (byte)0x01,
            (byte)0xab, (byte)0x3b, (byte)0x76, (byte)0xde, (byte)0x6c, (byte)0xa2,
            (byte)0xcb, (byte)0x7c, (byte)0x38, (byte)0xb6, (byte)0x9a, (byte)0x4b,
            (byte)0x28, (byte)0x01};

    public AppletTest() {
        // Change card type here if you want to use physical card
        setCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);
    }

    @BeforeAll
    public static void setUpClass() throws Exception {
    }

    @AfterAll
    public static void tearDownClass() throws Exception {
    }

    @BeforeEach
    public void setUpMethod() throws Exception {
    }

    @AfterEach
    public void tearDownMethod() throws Exception {
    }

    // Example test
    @Test
    public void testName() throws Exception {
        final CommandAPDU cmd = new CommandAPDU(0x00, 0x04, 0, 0);
        final ResponseAPDU responseAPDU = connect().transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        byte[] buf = responseAPDU.getBytes();
        Assert.assertNotNull(buf);
        Assert.assertEquals(new String(Arrays.copyOf(buf, buf.length - 2)), "hacker_volodya");
    }

    @Test
    public void testPublic() throws Exception {
        final CommandAPDU cmd = new CommandAPDU(0x00, 0x01, 0, 0);
        final ResponseAPDU responseAPDU = connect().transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        byte[] buf = responseAPDU.getBytes();
        Assert.assertNotNull(buf);
        int expLen = (buf[0] << 8) | buf[1];
        byte[] exp = Arrays.copyOfRange(buf, 2, expLen + 2);
        int modLen = (buf[2 + expLen] << 8) | buf[2 + expLen + 1];
        byte[] mod = Arrays.copyOfRange(buf, 2 + expLen + 2, 2 + expLen + 2 + modLen);
        Assert.assertArrayEquals(exp, RSA_PUB_KEY_EXP);
        Assert.assertArrayEquals(mod, RSA_PUB_PRIV_KEY_MOD);
    }

    @Test
    public void testAuth() throws Exception {
        final CommandAPDU cmd = new CommandAPDU(0x00, 0x02, 123, 0);
        final ResponseAPDU responseAPDU = connect().transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        byte[] buf = responseAPDU.getBytes();
        byte[] signature = Arrays.copyOf(buf, buf.length - 2);
        RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(
                new BigInteger(1, RSA_PUB_PRIV_KEY_MOD),
                new BigInteger(1, RSA_PUB_KEY_EXP));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubSpec);
        Signature signature1 = Signature.getInstance("SHA1withRSA");
        signature1.initVerify(pubKey);
        signature1.update(new byte[]{ 123 });
        boolean result = signature1.verify(signature);
        Assert.assertTrue(result);
    }

    @Test
    public void testWithdraw() throws Exception {
        CardManager cm = connect();

        final CommandAPDU cmd0 = new CommandAPDU(0x00, 0x03, 0, 0);
        final ResponseAPDU responseAPDU0 = cm.transmit(cmd0);
        Assert.assertEquals(0x9000, responseAPDU0.getSW());

        final CommandAPDU cmd = new CommandAPDU(0x00, 0x03, 900 >> 8, 900 & 255);
        final ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assert.assertEquals(0x9000, responseAPDU.getSW());

        final CommandAPDU cmd2 = new CommandAPDU(0x00, 0x03, 101 >> 8, 101 & 255);
        final ResponseAPDU responseAPDU2 = cm.transmit(cmd);
        Assert.assertEquals(0x6299, responseAPDU2.getSW());
    }
}
