package echizen.ryoma;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Random;

public class Main {

    public static void main(String[] args) throws IOException {
//        FHE fhe = new FHE();
//        KeyPair key = fhe.generateKeyPair(512);
//        ArrayList<BigInteger> encrypt = fhe.encrypt("00001111");
//        System.out.println(fhe.decrypt(encrypt));
//        key.save("D:/test.key", "D:/test.crt");
        Random random = new Random();
        int size = 256;
        size = (int) ((Math.pow(size, 2) + 1) * Math.log(size) / 2.0);
        System.out.println(size);
        ArrayList<Boolean> arrayList = new ArrayList<>();
        ArrayList<Integer> S = new ArrayList<>();
        int count = 0;
        for (int i = 0; i < size - 1; i++) {
            int b = random.nextInt((int) (size / Math.sqrt(256)));
            if (count < (int) Math.sqrt(256)) {
                arrayList.add(b == 0);
            } else {
                arrayList.add(false);
                System.out.println("1");
                continue;
            }
            if (b == 0) {
                S.add(i);
                count++;
            }
        }
        arrayList.add(true);
        S.add(size - 1);
        System.out.println(S.size());
    }
}
