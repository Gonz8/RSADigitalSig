/**
 * Created by Dominik on 2016-05-03.
 */
import java.math.BigInteger;
import java.security.Signature;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

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
            throw new SignatureException("No MD5 digest found");
        }
    }

    public void engineUpdate(byte b[], int offset, int length)
            throws SignatureException {
        try {
            md.update(b, offset, length);
        } catch (NullPointerException npe) {
            throw new SignatureException("No MD5 digest found");
        }
    }

    public byte[] engineSign() throws SignatureException {
        byte b[] = null;
        try {
            b = md.digest();
        } catch (NullPointerException npe) {
            throw new SignatureException("No MD5 digest found");
        }
        try {
            return RSAEngine.crypt(b, priv);
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
            b = RSAEngine.toByteArray(bn, RSAEngine.getByteLength(pub));
        } catch (NullPointerException npe) {
            throw new SignatureException("No MD5 digest found");
        }
        try {
            byte sig[] = RSAEngine.crypt(sigBytes, pub);
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

}
