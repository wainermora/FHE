package echizen.ryoma;

import com.google.gson.Gson;
import sun.misc.BASE64Encoder;

import java.math.BigInteger;
import java.util.ArrayList;

public class Main {

    public static void main(String[] args) {
        FHE fhe = new FHE();
        KeyPair keyPair = fhe.generateKeyPair(64);
        ArrayList<BigInteger> encrypt = fhe.encrypt("1111111011111111111");
        System.out.println(fhe.decrypt(encrypt));

        String encode = (new BASE64Encoder()).encode((new Gson()).toJson(keyPair).toString().getBytes());
//
//        System.out.println(encode);
    }
}
