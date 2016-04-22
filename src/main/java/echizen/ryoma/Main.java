package echizen.ryoma;

import java.io.IOException;
import java.util.ArrayList;

public class Main {

    public static void main(String[] args) throws IOException {
        FullHomomorphicEncryption fhe = new FullHomomorphicEncryption();
        KeyPair key = fhe.generateKeyPair(64);
        //key.save("D:/test.key", "D:/test.crt");
        ArrayList<EncryptMessage> c1 = fhe.encrypt("00001111");
        ArrayList<EncryptMessage> c2 = fhe.encrypt("00000001");
        System.out.println(fhe.decrypt(fhe.and(c1, c2)));
        System.out.println(fhe.decrypt(fhe.xor(c1, c2)));
        System.out.println(fhe.decrypt(fhe.add(c1, c2)));
    }
}