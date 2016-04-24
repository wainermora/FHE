package echizen.ryoma;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;

public class Decrypt {
    private PrivateKey private_key;

    public Decrypt(PrivateKey private_key) {
        this.private_key = private_key;
    }

    public String decrypt(ArrayList<EncryptMessage> EncryptMessage) {
        StringBuilder message = new StringBuilder();
        for (EncryptMessage encrypt : EncryptMessage) {
            message.append(decrypt(encrypt));
        }
        return message.toString();
    }

    private String decrypt(EncryptMessage encrypt) {
        BigDecimal sum = BigDecimal.ZERO;
        for (int s : private_key.S) {
            sum = sum.add(encrypt.Z.get(s));
        }
        return sum.toBigInteger().and(BigInteger.ONE).xor(encrypt.C.and(BigInteger.ONE)).toString();
    }
}
