package echizen.ryoma;

import java.math.BigInteger;

public class PublicKey {
    public BigInteger N;
    public BigInteger x;

    public PublicKey() {
    }

    public PublicKey(BigInteger n, BigInteger x) {
        N = n;
        this.x = x;
    }
}
