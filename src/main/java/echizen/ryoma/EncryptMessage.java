package echizen.ryoma;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;

public class EncryptMessage {
    public BigInteger C;
    public ArrayList<BigDecimal> Z;

    public EncryptMessage() {
        C = BigInteger.ZERO;
        Z = new ArrayList<>();
    }

    public EncryptMessage(BigInteger c) {
        C = c;
        Z = new ArrayList<>();
    }
}
