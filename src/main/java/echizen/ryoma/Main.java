package echizen.ryoma;

import java.io.IOException;
import java.util.ArrayList;

public class Main {

    public static void main(String[] args) throws IOException {
        FullHomomorphicEncryption fhe = new FullHomomorphicEncryption();
        KeyPair key = fhe.generateKeyPair(32);
        key.save("D:/test.key", "D:/test.crt");
        ArrayList<EncryptMessage> encrypt = fhe.encrypt("00001111");
        System.out.println(fhe.decrypt(encrypt));
    }
}