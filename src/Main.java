/**
 * Created by Dominik on 2016-04-26.
 */
import java.security.KeyPair;
import java.security.KeyPairGenerator;
//import java.security.Signature;

import sun.misc.BASE64Encoder;

public class Main {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair keyPair = kpg.genKeyPair();

        byte[] data = "test".getBytes("UTF8");
        byte[] data2 = "test2hsrhgsbf343wvdfsvdfgndghnfsfgsfsb ds dfsa wewe e fds sag adgf aadfgz dfg gdsfshdh434 4 64 43 3432345 45434544 gSADdsa nhdgnfnsgfbdgfnhmfjhtadgvfdb hdgmyukie57 6e5 5 45 y6 56 35343".getBytes("UTF8");

        RSADS sig = new RSADS();
        sig.initSign(keyPair.getPrivate());
        sig.update(data2);
        byte[] signatureBytes = sig.sign();
        System.out.println("Singature:" + signatureBytes.toString());

        sig.initVerify(keyPair.getPublic());
        sig.update(data2);

        System.out.println(sig.verify(signatureBytes));
    }
}