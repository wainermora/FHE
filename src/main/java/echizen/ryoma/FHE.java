package echizen.ryoma;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Random;

public class FHE {
    protected KeyPair Key;
    protected int SecurityParameter;

    public FHE() {
        Key = null;
    }

    public FHE(PrivateKey privateKey, PublicKey publicKey) {
        Key = new KeyPair(privateKey, publicKey);
        SecurityParameter = (int) Math.sqrt(Key.PrivateKey.p.bitCount());
    }

    public KeyPair generateKeyPair(int privateKeySize) {
        SecurityParameter = (int) Math.sqrt(privateKeySize);
        Key = new KeyPair();
        Key.PrivateKey = generatePrivateKey();
        Key.PublicKey = generatePublicKey();
        return Key;
    }

    private PrivateKey generatePrivateKey() {
        SecureRandom random = new SecureRandom();
        BigInteger high = new BigInteger("2").pow((int) Math.pow(SecurityParameter, 2)).subtract(BigInteger.ONE);
        BigInteger low = new BigInteger("2").pow((int) Math.pow(SecurityParameter, 2) - 1);
        BigInteger number;
        do {
            number = new BigInteger(high.bitLength(), 100, random);
        } while (number.compareTo(high) > 0 || number.compareTo(low) < 0);
        return new PrivateKey(number);
    }

    private PublicKey generatePublicKey() {
        SecureRandom random = new SecureRandom();
        BigInteger high = new BigInteger("2").pow((int) Math.pow(SecurityParameter, 4)).subtract(BigInteger.ONE);
        BigInteger low = new BigInteger("2").pow((int) Math.pow(SecurityParameter, 4) - 1);
        BigInteger q;
        do {
            q = new BigInteger(high.bitLength(), 100, random);
        } while (q.compareTo(high) > 0 || q.compareTo(low) < 0);
        BigInteger N = Key.PrivateKey.p.multiply(q);

        high = new BigInteger("2").pow((int) Math.pow(SecurityParameter, 5)).divide(Key.PrivateKey.p).subtract(BigInteger.ONE);
        low = new BigInteger("2").pow(high.bitCount() - 1);
        do {
            q = new BigInteger(high.bitLength(), random);
        } while (q.compareTo(high) > 0 || q.compareTo(low) < 0);

        BigInteger x = Key.PrivateKey.p.multiply(q).add(new BigInteger("2").multiply(r()));
        return new PublicKey(N, x);
    }

    private BigInteger r() {
        Random random = new Random();
        BigInteger high = new BigInteger("2").pow(SecurityParameter).subtract(BigInteger.ONE);
        BigInteger low = new BigInteger("2").pow(SecurityParameter - 1);
        BigInteger r;
        do {
            r = new BigInteger(high.bitLength(), random);
        } while (r.compareTo(high) > 0 || r.compareTo(low) < 0);
        r = r.subtract(low);
        return r;
    }

    public ArrayList<BigInteger> encrypt(String message) {
        ArrayList<BigInteger> encrypt = new ArrayList<>();
        for (int i = 0; i < message.length(); i++) {
            BigInteger x = new BigInteger(String.valueOf(message.charAt(i)));
            x = new BigInteger("2").multiply(r()).add(r().multiply(Key.PublicKey.x)).add(x).mod(Key.PublicKey.N);
            encrypt.add(x);
        }
        return encrypt;
    }

    public String decrypt(ArrayList<BigInteger> encryptMessage) {
        StringBuilder message = new StringBuilder();
        for (BigInteger encrypt : encryptMessage) {
            message.append(encrypt.mod(Key.PrivateKey.p).mod(new BigInteger("2")));
        }
        return message.toString();
    }
}
