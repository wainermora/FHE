package echizen.ryoma;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;

public class Main {

    public static void main(String[] args) throws IOException {
        FHE fhe = new FHE();
        KeyPair key = fhe.generateKeyPair(128);
        ArrayList<BigInteger> encrypt = fhe.encrypt("00001111");
        System.out.println(fhe.decrypt(encrypt));
        //key.save("D:/test.key", "D:/test.crt");
    }
}
