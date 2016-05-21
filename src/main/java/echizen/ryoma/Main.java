package echizen.ryoma;

import java.io.IOException;
import java.util.ArrayList;

public class Main {

    public static void main(String[] args) throws IOException {
        KeyPair FHE_KeyPair = new KeyPair(64);

        long StartTime = System.currentTimeMillis();
        FHE_KeyPair.generate();
        long EndTime = System.currentTimeMillis();
        System.out.println("生成密钥时间:\t" + (EndTime - StartTime) / 1000.0);

        Encrypt FHE_Encrypt = new Encrypt(FHE_KeyPair.getPublicKey());
        Decrypt FHE_Decrypt = new Decrypt(FHE_KeyPair.getPrivateKey());

        StartTime = System.currentTimeMillis();
        FHE_KeyPair.save("D:/test.key", "D:/test.crt");
        EndTime = System.currentTimeMillis();
        System.out.println("保存密钥时间:\t" + (EndTime - StartTime) / 1000.0);

        ArrayList<EncryptMessage> c1 = FHE_Encrypt.encrypt("11110000");
        ArrayList<EncryptMessage> c2 = FHE_Encrypt.encrypt("00001111");
        StartTime = System.currentTimeMillis();
        System.out.println(FHE_Decrypt.decrypt(FHE_Encrypt.and(c1, c2)));
        EndTime = System.currentTimeMillis();
        System.out.println("AND运算的时间:\t" + (EndTime - StartTime) / 1000.0 + "s");

        StartTime = System.currentTimeMillis();
        System.out.println(FHE_Decrypt.decrypt(FHE_Encrypt.xor(c1, c2)));
        EndTime = System.currentTimeMillis();
        System.out.println("XOR运算的时间:\t" + (EndTime - StartTime) / 1000.0 + "s");

        StartTime = System.currentTimeMillis();
        System.out.println(FHE_Decrypt.decrypt(FHE_Encrypt.or(c1, c2)));
        EndTime = System.currentTimeMillis();
        System.out.println("OR运算的时间:\t" + (EndTime - StartTime) / 1000.0 + "s");
    }
}