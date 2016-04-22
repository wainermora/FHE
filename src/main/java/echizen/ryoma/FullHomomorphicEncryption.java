package echizen.ryoma;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Random;

public class FullHomomorphicEncryption {
    protected KeyPair Key;
    protected int KeySize;

    public FullHomomorphicEncryption() {
        Key = null;
    }

    public FullHomomorphicEncryption(PrivateKey privateKey, PublicKey publicKey) {
        Key = new KeyPair(privateKey, publicKey);
        KeySize = Key.PrivateKey.p.bitCount();
    }

    public KeyPair generateKeyPair(int keySize) {
        Key = new KeyPair();
        KeySize = keySize;
        Key.PrivateKey = generatePrivateKey();
        Key.PublicKey = generatePublicKey();
        return Key;
    }

    private PrivateKey generatePrivateKey() {
        SecureRandom random = new SecureRandom();
        BigInteger high = new BigInteger("2").pow(KeySize).subtract(BigInteger.ONE);
        BigInteger low = new BigInteger("2").pow(KeySize - 1);
        BigInteger number;
        do {
            number = new BigInteger(high.bitLength(), 100, random);
        } while (number.compareTo(high) > 0 || number.compareTo(low) < 0);
        return new PrivateKey(number);
    }

    private PublicKey generatePublicKey() {
        SecureRandom secureRandom = new SecureRandom();
        BigInteger q = new BigInteger(KeySize, 100, secureRandom);
        q = q.multiply(new BigInteger(KeySize, 100, secureRandom));
        BigInteger N = Key.PrivateKey.p.multiply(q);

        BigInteger high = new BigInteger("2").pow((int) Math.pow(KeySize, 5.0 / 2.0)).divide(Key.PrivateKey.p).subtract(BigInteger.ONE);
        Random random = new Random();
        do {
            q = new BigInteger(high.bitLength(), random);
        } while (q.compareTo(high) > 0 || q.mod(new BigInteger("2")) == BigInteger.ZERO);
        BigInteger x = Key.PrivateKey.p.multiply(q).add(new BigInteger("2").multiply(r()));
        return new PublicKey(N, x);
    }

    private BigInteger r() {
        Random random = new Random();
        BigInteger high = new BigInteger("2").pow((int) Math.sqrt(KeySize)).subtract(BigInteger.ONE);
        BigInteger low = new BigInteger("2").pow((int) Math.sqrt(KeySize) - 1);
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
            BigInteger c = new BigInteger(String.valueOf(message.charAt(i)));
            c = c.add(new BigInteger("2").multiply(r())).add(r().multiply(Key.PublicKey.x)).mod(Key.PublicKey.N);
            encrypt.add(c);
        }
        return encrypt;
    }

    public String decrypt(ArrayList<BigInteger> encryptMessage) {
        StringBuilder message = new StringBuilder();
        for (BigInteger encrypt : encryptMessage) {
            message.append(encrypt.and(BigInteger.ONE).xor(encrypt.divide(Key.PrivateKey.p).and(BigInteger.ONE)));
        }
        return message.toString();
    }
}
