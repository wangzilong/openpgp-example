import org.bouncycastle.openpgp.PGPPublicKey;

import java.io.ByteArrayOutputStream;

public class KeyPairPGP {
    private byte[] privateKey;
    private byte[] publicKey;

    public KeyPairPGP() {
        ByteArrayOutputStream privateKey = new ByteArrayOutputStream();
        ByteArrayOutputStream publicKey = new ByteArrayOutputStream();
        PGPUtils.generateKeyPair(privateKey, publicKey);
        this.privateKey = privateKey.toByteArray();
        this.publicKey = publicKey.toByteArray();
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public PGPPublicKey getPGPPublicKey(){
        return PGPUtils.readPublicKey(publicKey);
    }
}
