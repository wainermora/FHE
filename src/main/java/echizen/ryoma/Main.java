package echizen.ryoma;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;

public class Main {

    public static void main(String[] args) throws IOException {
        FHE fhe = new FHE();
        KeyPair keyPair = fhe.generateKeyPair(64);
        ArrayList<BigInteger> encrypt = fhe.encrypt("1111111011111111111");
        System.out.println(fhe.decrypt(encrypt));

        //keyPair.save("D:/test.key", "D:/test.crt");
    }
}
