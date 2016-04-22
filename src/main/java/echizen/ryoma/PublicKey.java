package echizen.ryoma;

import java.math.BigDecimal;
import java.math.BigInteger;

public class PublicKey {
    public BigInteger N;
    public BigInteger x;
    public int seed;
    public BigDecimal y;

    public PublicKey() {
    }

    public PublicKey(BigInteger n, BigInteger x, int seed, BigDecimal y) {
        N = n;
        this.x = x;
        this.seed = seed;
        this.y = y;
    }
}
