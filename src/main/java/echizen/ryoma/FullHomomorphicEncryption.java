package echizen.ryoma;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

public class FullHomomorphicEncryption {
    protected KeyPair Key;
    protected int KeySize;
    private ArrayList<BigDecimal> Y;

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
        SecureRandom secureRandom = new SecureRandom();
        BigInteger high = new BigInteger("2").pow(KeySize).subtract(BigInteger.ONE);
        BigInteger low = new BigInteger("2").pow(KeySize - 1);
        BigInteger p;
        do {
            p = new BigInteger(high.bitLength(), 100, secureRandom);
        } while (p.compareTo(high) > 0 || p.compareTo(low) < 0);

        Set<Integer> S = new HashSet<>();
        int k = (int) Math.pow(KeySize, 5.0 / 2.0) + 2;
        BigInteger K = new BigInteger("2").pow(k).divide(p);
        Random random = new Random();
        int count = (int) Math.sqrt(KeySize);
        for (int i = 0; i < count - 1; i++) {
            int RandomNumer = random.nextInt(k - 1);
            if (!S.contains(RandomNumer)) {
                S.add(RandomNumer);
            } else {
                i--;
            }
        }
        S.add(k - 1);
        return new PrivateKey(p, S);
    }

    private void generateY(int seed) {
        int k = (int) Math.pow(KeySize, 5.0 / 2.0) + 2;
        BigInteger K = new BigInteger("2").pow(k).divide(Key.PrivateKey.p);
        Random random = new Random(seed);
        ArrayList<BigInteger> U = new ArrayList<>();
        BigInteger sum = BigInteger.ZERO;
        BigInteger high = new BigInteger("2").pow(k + 1).subtract(BigInteger.ONE);
        BigInteger u;
        for (int i = 0; i < k - 1; i++) {
            u = new BigInteger(k + 1, random);
            U.add(u);
            sum.add(u);
        }
        u = K.subtract(sum).mod(new BigInteger("2").pow(k + 1));
        U.add(u);
        high = new BigInteger("2").pow(k);
        Y = new ArrayList<>();
        for (int i = 0; i < k; i++) {
            Y.add(new BigDecimal(U.get(i)).divide(new BigDecimal(high), (int) (2.0 * Math.pow(KeySize, 5.0 / 2.0 - 1) * Math.log10(2) + 3), BigDecimal.ROUND_HALF_UP));
        }
    }

    private PublicKey generatePublicKey() {
        SecureRandom secureRandom = new SecureRandom();
        BigInteger q = new BigInteger((int) Math.pow(KeySize, 5.0 / 2.0 - 1), 100, secureRandom);
        BigInteger N = Key.PrivateKey.p.multiply(q);

        BigInteger high = new BigInteger("2").pow((int) Math.pow(KeySize, 5.0 / 2.0)).divide(Key.PrivateKey.p).subtract(BigInteger.ONE);
        Random random = new Random();
        do {
            q = new BigInteger(high.bitLength(), random);
        } while (q.compareTo(high) > 0 || q.mod(new BigInteger("2")) == BigInteger.ZERO);
        BigInteger x = Key.PrivateKey.p.multiply(q).add(new BigInteger("2").multiply(r()));

        int k = (int) Math.pow(KeySize, 5.0 / 2.0) + 2;
        BigInteger K = new BigInteger("2").pow(k).divide(Key.PrivateKey.p);

        int seed = random.nextInt();
        generateY(seed);
        return new PublicKey(N, x, seed, Y.get(Y.size() - 1));
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
