package applet;

import javacard.framework.*;
import javacard.security.*;

public class MainApplet extends Applet implements MultiSelectable {
    private static final byte PUBLIC_INS = (byte) 0x01;
    private static final byte AUTH_INS = (byte) 0x02;
    private static final byte WITHDRAW_INS = (byte) 0x03;
    private static final byte NAME_INS = (byte) 0x04;

    private static final byte[] CARDHOLDER = new byte[]{
            0x68, 0x61, 0x63, 0x6b, 0x65, 0x72, 0x5f,
            0x76, 0x6f, 0x6c, 0x6f, 0x64, 0x79, 0x61
    };

    Signature sig;

    RSAPublicKey pubKey;
    RSAPrivateKey privKey;

    private short balance;

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

    private final byte[] transientMemory;

    public MainApplet(byte[] buffer, short offset, byte length) {
        transientMemory = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        pubKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,KeyBuilder.LENGTH_RSA_512,false);
        privKey = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,KeyBuilder.LENGTH_RSA_512,false);
        privKey.setExponent(RSA_PRIV_KEY_EXP,(short)0,(short)RSA_PRIV_KEY_EXP.length);
        privKey.setModulus(RSA_PUB_PRIV_KEY_MOD,(short)0,(short)RSA_PUB_PRIV_KEY_MOD.length);
        pubKey.setExponent(RSA_PUB_KEY_EXP,(short)0,(short)RSA_PUB_KEY_EXP.length);
        pubKey.setModulus(RSA_PUB_PRIV_KEY_MOD,(short)0,(short)RSA_PUB_PRIV_KEY_MOD.length);
        sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1,false);
        balance = 1000;
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MainApplet(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buffer = apdu.getBuffer();
        // Now determine the requested instruction:
        switch (buffer[ISO7816.OFFSET_INS]) {
            case PUBLIC_INS:
                getPublicKey(apdu);
                return;
            case AUTH_INS:
                authenticate(apdu);
                return;
            case WITHDRAW_INS:
                withdraw(apdu);
                return;
            case NAME_INS:
                getCardholderName(apdu);
                return;
            default:
                // We do not support any other INS values
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void getPublicKey(APDU apdu) {
        // формат:
        // short expLen;
        // byte[] exp;
        // short modLen;
        // byte[] mod;

        short len = serializeKey(pubKey, transientMemory, (short) 0);
        apdu.setOutgoing();
        apdu.setOutgoingLength(len);
        apdu.sendBytesLong(transientMemory, (short) 0, len);


    }

    private void authenticate(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        sig.init(privKey, Signature.MODE_SIGN);
        short sigLen = sig.sign(buffer, ISO7816.OFFSET_P1, (short) 1, transientMemory, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(sigLen);
        apdu.sendBytesLong(transientMemory, (short)0, sigLen);
    }

    private void withdraw(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short withdraw_amount = Util.getShort(buffer, ISO7816.OFFSET_P1);
        if (balance < withdraw_amount) {
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) 2);
            Util.setShort(transientMemory, (short) 0, balance);
            apdu.sendBytesLong(transientMemory, (short)0, (short) 2);
            ISOException.throwIt((short) 0x6299);
        }

        balance -= withdraw_amount;

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 2);
        Util.setShort(transientMemory, (short) 0, balance);
        apdu.sendBytesLong(transientMemory, (short)0, (short) 2);
    }

    private void getCardholderName(APDU apdu) {
        Util.arrayCopyNonAtomic(CARDHOLDER, (short) 0, transientMemory, (short) 0, (short) CARDHOLDER.length);
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) CARDHOLDER.length);
        apdu.sendBytesLong(transientMemory, (short) 0, (short) CARDHOLDER.length);
    }

    public boolean select(boolean b) {
        return true;
    }

    public void deselect(boolean b) {

    }

    //reads the key object and stores it into the buffer
    private final short serializeKey(RSAPublicKey key, byte[] buffer, short offset) {
        short expLen = key.getExponent(buffer, (short) (offset + 2));
        Util.setShort(buffer, offset, expLen);
        short modLen = key.getModulus(buffer, (short) (offset + 4 + expLen));
        Util.setShort(buffer, (short) (offset + 2 + expLen), modLen);
        return (short) (4 + expLen + modLen);
    }
}
