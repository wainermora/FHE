package echizen.ryoma;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;

public class PublicKey {
    public BigInteger N;
    public BigInteger x;
    public ArrayList<BigDecimal> Y;

    public PublicKey() {
    }

    public PublicKey(BigInteger n, BigInteger x, ArrayList<BigDecimal> y) {
        N = n;
        this.x = x;
        Y = y;
    }
}
