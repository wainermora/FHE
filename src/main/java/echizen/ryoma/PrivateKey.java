package echizen.ryoma;

import java.math.BigInteger;
import java.util.Set;

public class PrivateKey {
    public BigInteger p;
    public Set<Integer> S;

    public PrivateKey() {
    }

    public PrivateKey(BigInteger p, Set<Integer> s) {
        this.p = p;
        S = s;
    }
}
