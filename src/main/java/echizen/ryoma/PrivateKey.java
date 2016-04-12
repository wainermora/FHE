package echizen.ryoma;

import java.math.BigInteger;

public class PrivateKey {
    public BigInteger p;

    public PrivateKey() {
    }

    public PrivateKey(BigInteger p) {
        this.p = p;
    }
}
