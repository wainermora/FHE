package echizen.ryoma;

import java.io.IOException;
import java.util.ArrayList;

public class Main {

    public static void main(String[] args) throws IOException {
        KeyPair FHE_KeyPair = new KeyPair(64);
        FHE_KeyPair.generate();

        Encrypt FHE_Encrypt = new Encrypt(FHE_KeyPair.getPublicKey());
        Decrypt FHE_Decrypt = new Decrypt(FHE_KeyPair.getPrivateKey());

        //FHE_KeyPair.save("D:/test.key", "D:/test.crt");

        ArrayList<EncryptMessage> c1 = FHE_Encrypt.encrypt("11110000");
        ArrayList<EncryptMessage> c2 = FHE_Encrypt.encrypt("00001111");
        System.out.println(FHE_Decrypt.decrypt(FHE_Encrypt.and(c1, c2)));
        System.out.println(FHE_Decrypt.decrypt(FHE_Encrypt.xor(c1, c2)));
        System.out.println(FHE_Decrypt.decrypt(FHE_Encrypt.or(c1, c2)));
    }
}