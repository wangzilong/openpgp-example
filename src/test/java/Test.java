import org.bouncycastle.openpgp.PGPPublicKey;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by steven.wang on 21/07/17.
 *
 */
public class Test {

    private static final byte[] clearData = "1234567890".getBytes();


    public static void main(String[] args) {
        System.out.println("==> generate keypair 1");
        KeyPairPGP keyPair1 = new KeyPairPGP();
        System.out.println("==> generate keypair 2");
        KeyPairPGP keyPair2 = new KeyPairPGP();


        System.out.println("==> encrypt with 2 public keys");
        Set<PGPPublicKey> publicKeys = new HashSet<PGPPublicKey>();
        publicKeys.add(keyPair1.getPGPPublicKey());
        publicKeys.add(keyPair2.getPGPPublicKey());

        ByteArrayOutputStream enc_os = new ByteArrayOutputStream();
        PGPUtils.encrypt(enc_os, clearData, publicKeys);

        byte[] encryptedByteArray = enc_os.toByteArray();
        assert !Arrays.equals(clearData, encryptedByteArray);
        System.out.println("<== encrypt data : ");
        System.out.println(new String(encryptedByteArray));

        System.out.println("==> decrypt by private key 1");
        ByteArrayOutputStream dec_os = new ByteArrayOutputStream();
        PGPUtils.decrypt(encryptedByteArray, keyPair1.getPrivateKey(), dec_os);
        byte[] decryptedByteArray = dec_os.toByteArray();
        boolean bool = Arrays.equals(clearData, decryptedByteArray);
        System.out.println("<== decrypt by private key 1, result : " + Arrays.equals(clearData, dec_os.toByteArray()));

        System.out.println("==> decrypt by private key 2");
        dec_os = new ByteArrayOutputStream();
        PGPUtils.decrypt(encryptedByteArray, keyPair2.getPrivateKey(), dec_os);
        decryptedByteArray = dec_os.toByteArray();
        bool = Arrays.equals(clearData, decryptedByteArray);
        System.out.println("<== decrypt by private key 1, result : " + bool);

    }
}
