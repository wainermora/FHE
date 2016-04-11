package echizen.ryoma;

import java.math.BigInteger;
import java.util.ArrayList;

public class KeyPair {
    private BigInteger PrivateKey;
    private ArrayList<BigInteger> PublicKey;

    public KeyPair() {
    }

    public KeyPair(BigInteger secretKey, ArrayList<BigInteger> publicKey) {
        PrivateKey = secretKey;
        PublicKey = publicKey;
    }

    public BigInteger getPrivateKey() {
        return PrivateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        PrivateKey = privateKey;
    }

    public ArrayList<BigInteger> getPublicKey() {
        return PublicKey;
    }

    public void setPublicKey(ArrayList<BigInteger> publicKey) {
        PublicKey = publicKey;
    }
}
