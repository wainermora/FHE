package echizen.ryoma;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Random;

public class FHE {
    protected KeyPair keyPair;
    protected int SecurityParameter;
    private int NoiseSize;
    private int PrivateKeySize;
    private int PublicKeyIntegerSize;
    private int PublicKeyCount;
    private int SecondNoiseParameter;

    public FHE() {
        keyPair = null;
    }

    public FHE(BigInteger privateKey, ArrayList<BigInteger> publicKey) {
        keyPair = new KeyPair(privateKey, publicKey);
        SecurityParameter = (int) Math.sqrt(keyPair.getPrivateKey().bitCount());
        generateParameter();
    }

    private void generateParameter() {
        NoiseSize = 2 * SecurityParameter;
        PrivateKeySize = (int) Math.pow(SecurityParameter, 2);
        PublicKeyIntegerSize = (int) Math.pow(SecurityParameter, 5);
        PublicKeyCount = (int) Math.sqrt(Math.pow(SecurityParameter, 3));
        SecondNoiseParameter = 3 * SecurityParameter;
    }

    public KeyPair generateKeyPair(int privateKeySize) {
        SecurityParameter = (int) Math.sqrt(privateKeySize);
        generateParameter();
        keyPair = new KeyPair();
        keyPair.setPrivateKey(generatePrivateKey());
        keyPair.setPublicKey(generatePublicKey());
        return keyPair;
    }

    private BigInteger generateOdd(int length) {
        Random random = new Random();
        BigInteger base = new BigInteger("2").pow(length - 1);
        BigInteger number;
        do {
            number = base.add(new BigInteger(base.bitLength(), random));
        } while (number.mod(new BigInteger("2")) == BigInteger.ZERO);
        return number;
    }

    private BigInteger generatePrivateKey() {
        return generateOdd(PrivateKeySize);
    }

    private ArrayList<BigInteger> generatePublicKey() {
        ArrayList<BigInteger> Q = new ArrayList<>();
        BigInteger high = new BigInteger("2").pow(PublicKeyIntegerSize).divide(keyPair.getPrivateKey());
        Random random = new Random();
        for (int i = 0; i < PublicKeyCount; i++) {
            BigInteger q;
            do {
                q = new BigInteger(high.bitLength(), random);
            } while (q.compareTo(high) >= 0);
            Q.add(q);
        }
        Collections.sort(Q);
        Collections.reverse(Q);
        if (Q.get(0).mod(new BigInteger("2")) == BigInteger.ZERO) {
            Q.set(0, Q.get(0).add(BigInteger.ONE));
        }

        ArrayList<BigInteger> PublicKeys = new ArrayList<>();
        high = new BigInteger("2").pow(NoiseSize).subtract(BigInteger.ONE);
        BigInteger publicKey = Q.get(0).multiply(keyPair.getPrivateKey());
        PublicKeys.add(publicKey);
        for (int i = 0; i < PublicKeyCount; i++) {
            BigInteger r;
            do {
                r = new BigInteger(high.bitLength(), random);
            } while (r.compareTo(high) >= 0);
            publicKey = Q.get(i).multiply(keyPair.getPrivateKey()).add((new BigInteger("2").multiply(r)));
            PublicKeys.add(publicKey);
        }
        return PublicKeys;
    }

    public ArrayList<BigInteger> encrypt(String message) {
        ArrayList<BigInteger> encrypt = new ArrayList<>();
        for (int i = 0; i < message.length(); i++) {
            BigInteger x = new BigInteger(String.valueOf(message.charAt(i)));
            x = new BigInteger("2").multiply(noise()).add(sum()).add(x).mod(keyPair.getPublicKey().get(0));
            encrypt.add(x);
        }
        return encrypt;
    }

    private BigInteger sum() {
        int SubSize = (int) (Math.random() * PublicKeyCount);
        if (SubSize < 1) {
            SubSize = 1;
        }
        BigInteger sum = BigInteger.ZERO;
        for (int i = 1; i < SubSize; i++) {
            sum = sum.add(keyPair.getPublicKey().get(i)).mod(keyPair.getPublicKey().get(0));
        }
        return sum.multiply(new BigInteger("2"));
    }

    private BigInteger noise() {
        BigInteger high = new BigInteger("2").pow(NoiseSize).subtract(BigInteger.ONE);
        BigInteger noise;
        Random random = new Random();
        do {
            noise = new BigInteger(high.bitLength(), random);
        } while (noise.compareTo(high) >= 0);
        return noise;
    }

    public String decrypt(ArrayList<BigInteger> encryptMessage) {
        StringBuilder message = new StringBuilder();
        for (BigInteger encrypt : encryptMessage) {
            message.append(encrypt.mod(keyPair.getPrivateKey()).mod(new BigInteger("2")));
        }
        return message.toString();
    }
}
