/**
 * Created by Dominik on 2016-05-03.
 */
import java.math.BigInteger;
import java.security.Signature;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

import javax.crypto.BadPaddingException;
import sun.security.jca.JCAUtil;

public class RSADS extends Signature implements Cloneable {
    private RSAPublicKey pub;
    private RSAPrivateKey priv;
    private MessageDigest md;

    public RSADS() throws NoSuchAlgorithmException {
        super("RSADS");
        md = MessageDigest.getInstance("MD5");
    }

    public void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException {
        try {
            pub = (RSAPublicKey) publicKey;
        } catch (ClassCastException cce) {
            throw new InvalidKeyException("Wrong public key type");
        }
    }

    public void engineInitSign(PrivateKey privateKey)
            throws InvalidKeyException {
        try {
            priv = (RSAPrivateKey) privateKey;
        } catch (ClassCastException cce) {
            throw new InvalidKeyException("Wrong private key type");
        }
    }

    public void engineUpdate(byte b) throws SignatureException {
        try {
            md.update(b);
        } catch (NullPointerException npe) {
            throw new SignatureException("No SHA digest found");
        }
    }

    public void engineUpdate(byte b[], int offset, int length)
            throws SignatureException {
        try {
            md.update(b, offset, length);
        } catch (NullPointerException npe) {
            throw new SignatureException("No SHA digest found");
        }
    }

    public byte[] engineSign() throws SignatureException {
        byte b[] = null;
        try {
            b = md.digest();
            //System.out.println("msgHASH:" + b.toString());
        } catch (NullPointerException npe) {
            throw new SignatureException("No SHA digest found");
        }
        try {
            return crypt(b, priv);
        } catch (Exception e) {
            throw new SignatureException("Could not sign data", e);
        }
    }

    public boolean engineVerify(byte[] sigBytes)
            throws SignatureException {
        byte b[] = null;
        try {
            b = md.digest();
            //proba
            BigInteger bn = new BigInteger(1, b);
            b = toByteArray(bn, getByteLength(pub));
        } catch (NullPointerException npe) {
            throw new SignatureException("No SHA digest found");
        }
        try {
            byte sig[] = crypt(sigBytes, pub);
            return MessageDigest.isEqual(sig, b);
        } catch (Exception e) {
            throw new SignatureException("Could not sign data", e);
        }
    }

    public void engineSetParameter(String param, Object value) {
        throw new InvalidParameterException("No parameters");
    }

    public void engineSetParameter(AlgorithmParameterSpec aps) {
        throw new InvalidParameterException("No parameters");
    }

    public Object engineGetParameter(String param) {
        throw new InvalidParameterException("No parameters");
    }

    public void engineReset() {
    }

    // RSACore

    private byte[] crypt(byte s[], RSAPublicKey key)
            throws BadPaddingException {
//        BigInteger n = key.getModulus();
//        BigInteger exp = key.getPublicExponent();
//        byte d[] = s;
//        return d;
        return doCrypt(s, key.getModulus(), key.getPublicExponent());
    }

    private byte[] crypt(byte s[], RSAPrivateKey key)
            throws BadPaddingException {
//        RSAParams p = key.getParams();
//        int rotValue = p.getP().intValue();
//        byte d[] = rot(s, (byte) rotValue);
        //BigInteger n = key.getModulus();
        //BigInteger exp = key.get;
//        byte d[] = s;
//        return d;
//        if (key instanceof RSAPrivateCrtKey) {
//            return doCrtCrypt(s, (RSAPrivateCrtKey)key);
//        } else {
            return doCrypt(s, key.getModulus(), key.getPrivateExponent());
        //}
    }

    private byte[] doCrypt(byte[] msg, BigInteger n, BigInteger exp)
            throws BadPaddingException{
        BigInteger m = parseMsg(msg, n);
        BigInteger c = m.modPow(exp, n);
        return toByteArray(c, getByteLength(n));
    }

    private byte[] rot(byte in[], byte rotValue) {
        byte out[] = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ rotValue);
        }
        return out;
    }

    private static byte[] doCrtCrypt(byte[] msg, RSAPrivateCrtKey key)
            throws BadPaddingException {
        BigInteger n = key.getModulus();
        BigInteger c = parseMsg(msg, n);
        BigInteger p = key.getPrimeP();
        BigInteger q = key.getPrimeQ();
        BigInteger dP = key.getPrimeExponentP();
        BigInteger dQ = key.getPrimeExponentQ();
        BigInteger qInv = key.getCrtCoefficient();

        BlindingParameters params;
        if (ENABLE_BLINDING) {
            params = getBlindingParameters(key);
            c = c.multiply(params.re).mod(n);
        } else {
            params = null;
        }

        // m1 = c ^ dP mod p
        BigInteger m1 = c.modPow(dP, p);
        // m2 = c ^ dQ mod q
        BigInteger m2 = c.modPow(dQ, q);

        // h = (m1 - m2) * qInv mod p
        BigInteger mtmp = m1.subtract(m2);
        if (mtmp.signum() < 0) {
            mtmp = mtmp.add(p);
        }
        BigInteger h = mtmp.multiply(qInv).mod(p);

        // m = m2 + q * h
        BigInteger m = h.multiply(q).add(m2);

        if (params != null) {
            m = m.multiply(params.rInv).mod(n);
        }

        return toByteArray(m, getByteLength(n));
     }

    private static BigInteger parseMsg(byte[] msg, BigInteger n)
            throws BadPaddingException {
        BigInteger m = new BigInteger(1, msg);
        if (m.compareTo(n) >= 0) {
            throw new BadPaddingException("Message is larger than modulus");
        }
        return m;
    }

    private static byte[] toByteArray(BigInteger bi, int len) {
        byte[] b = bi.toByteArray();
        int n = b.length;
        if (n == len) {
            return b;
        }
        // BigInteger prefixed a 0x00 byte for 2's complement form, remove it
        if ((n == len + 1) && (b[0] == 0)) {
            byte[] t = new byte[len];
            System.arraycopy(b, 1, t, 0, len);
            return t;
        }
        // must be smaller
        assert (n < len);
        byte[] t = new byte[len];
        System.arraycopy(b, 0, t, (len - n), n);
        return t;
    }

    public static int getByteLength(BigInteger b) {
        int n = b.bitLength();
        return (n + 7) >> 3;
    }

    public static int getByteLength(RSAKey key) {
        return getByteLength(key.getModulus());
    }

    // globally enable/disable use of blinding
    private final static boolean ENABLE_BLINDING = true;

    // maximum number of times that we will use a set of blinding parameters
    // value suggested by Paul Kocher (quoted by NSS)
    private final static int BLINDING_MAX_REUSE = 50;

    // cache for blinding parameters. Map<BigInteger,BlindingParameters>
    // use a weak hashmap so that cached values are automatically cleared
    // when the modulus is GC'ed
    private final static Map<BigInteger,BlindingParameters> blindingCache =
            new WeakHashMap<BigInteger,BlindingParameters>();

    private static final class BlindingParameters {
        // e (RSA public exponent)
        final BigInteger e;
        // r ^ e mod n
        final BigInteger re;
        // inverse of r mod n
        final BigInteger rInv;
        // how many more times this parameter object can be used
        private volatile int remainingUses;
        BlindingParameters(BigInteger e, BigInteger re, BigInteger rInv) {
            this.e = e;
            this.re = re;
            this.rInv = rInv;
            // initialize remaining uses, subtract current use now
            remainingUses = BLINDING_MAX_REUSE - 1;
        }
        boolean valid(BigInteger e) {
            int k = remainingUses--;
            return (k > 0) && this.e.equals(e);
        }
    }

    private static BlindingParameters getBlindingParameters (RSAPrivateCrtKey key) {
        BigInteger modulus = key.getModulus();
        BigInteger e = key.getPublicExponent();
        BlindingParameters params;
        // we release the lock between get() and put()
        // that means threads might concurrently generate new blinding
        // parameters for the same modulus. this is only a slight waste
        // of cycles and seems preferable in terms of scalability
        // to locking out all threads while generating new parameters
        synchronized (blindingCache) {
            params = blindingCache.get(modulus);
        }
        if ((params != null) && params.valid(e)) {
            return params;
        }
        int len = modulus.bitLength();
        SecureRandom random = JCAUtil.getSecureRandom();
        BigInteger r = new BigInteger(len, random).mod(modulus);
        BigInteger re = r.modPow(e, modulus);
        BigInteger rInv = r.modInverse(modulus);
        params = new BlindingParameters(e, re, rInv);
        synchronized (blindingCache) {
            blindingCache.put(modulus, params);
        }
        return params;
    }
}
