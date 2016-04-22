package echizen.ryoma;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

public class FullHomomorphicEncryption {
    private KeyPair Key;
    private int KeySize;

    KeyPair generateKeyPair(int keySize) {
        Key = new KeyPair();
        KeySize = keySize;
        Key.PrivateKey = generatePrivateKey();
        Key.PublicKey = generatePublicKey();

        Key.PublicKey.S = new ArrayList<>();
        int k = (int) Math.pow(KeySize, 3.0 / 2.0) + 2;
        for (int i = 0; i < k; i++) {
            BigInteger integer = BigInteger.ZERO;
            if (Key.PublicKey.S.contains(i)) {
                integer = BigInteger.ONE;
            }
            Key.PublicKey.S.add(encrypt(integer));
        }
        return Key;
    }

    private PrivateKey generatePrivateKey() {
        SecureRandom secureRandom = new SecureRandom();
        BigInteger p = new BigInteger(KeySize, 100, secureRandom);

        Set<Integer> S = new HashSet<>();
        int k = (int) Math.pow(KeySize, 3.0 / 2.0) + 2;
        Random random = new Random();
        int count = (int) Math.sqrt(KeySize);
        for (int i = 0; i < count - 1; i++) {
            int number = random.nextInt(k - 1);
            if (!S.contains(number)) {
                S.add(number);
            } else {
                i--;
            }
        }
        S.add(k - 1);
        return new PrivateKey(p, S);
    }

    private PublicKey generatePublicKey() {
        int length = 5 * KeySize;
        SecureRandom secureRandom = new SecureRandom();
        BigInteger N = Key.PrivateKey.p.multiply(new BigInteger(length, secureRandom));

        Random random = new Random();
        BigInteger integer;
        do {
            integer = new BigInteger(length, random);
        } while (integer.mod(new BigInteger("2")).equals(BigInteger.ZERO));
        BigInteger x = Key.PrivateKey.p.multiply(integer).add(new BigInteger("2").multiply(r()));

        int k = (int) Math.pow(KeySize, 3.0 / 2.0) + 2;
        BigInteger K = new BigInteger("2").pow(k).divide(Key.PrivateKey.p);
        ArrayList<BigInteger> U = new ArrayList<>();

        BigInteger u;
        for (int i = 0; i < k - 1; i++) {
            do {
                u = new BigInteger(k + 1, random);
            } while (U.contains(u));
            U.add(u);
        }
        U.add(BigInteger.ZERO);
        BigInteger sum = BigInteger.ZERO;
        for (int s : Key.PrivateKey.S) {
            sum = sum.add(U.get(s));
        }
        u = K.subtract(sum).mod(new BigInteger("2").pow(k + 1));
        U.set(U.size() - 1, u);

        int accurate = (int) (Math.pow(KeySize, 3.0 / 2.0) * Math.log10(2));
        BigInteger Mod = new BigInteger("2").pow(k);
        Key.PublicKey.Y = new ArrayList<>();
        for (int i = 0; i < k; i++) {
            Key.PublicKey.Y.add(new BigDecimal(U.get(i)).divide(new BigDecimal(Mod), accurate, BigDecimal.ROUND_DOWN));
        }
        return new PublicKey(N, x, Key.PublicKey.Y);
    }

    private BigInteger r() {
        int length = (int) Math.sqrt(KeySize);
        Random random = new Random();
        return new BigInteger(length, random);
    }

    public ArrayList<EncryptMessage> encrypt(String message) {
        ArrayList<EncryptMessage> EncryptMessage = new ArrayList<>();
        for (int i = 0; i < message.length(); i++) {
            EncryptMessage encrypt = new EncryptMessage();
            encrypt.C = new BigInteger(String.valueOf(message.charAt(i))).add(new BigInteger("2").multiply(r())).add(r().multiply(Key.PublicKey.x)).mod(Key.PublicKey.N);
            encrypt = encrypt(encrypt);
            EncryptMessage.add(encrypt);
        }
        return EncryptMessage;
    }

    private EncryptMessage encrypt(EncryptMessage encrypt) {
        encrypt.Z.clear();
        int accuracy = (int) (KeySize * Math.log10(2) + 3);
        for (BigDecimal y : Key.PublicKey.Y) {
            BigDecimal decimal = y.multiply(new BigDecimal(encrypt.C));
            BigInteger integer = decimal.toBigInteger();
            decimal = decimal.subtract(new BigDecimal(integer)).setScale(accuracy, BigDecimal.ROUND_DOWN);
            integer = integer.mod(new BigInteger("2"));
            decimal = decimal.add(new BigDecimal(integer)).remainder(new BigDecimal("2"));
            encrypt.Z.add(decimal);
        }
        return encrypt;
    }

    private BigInteger encrypt(BigInteger encrypt) {
        return encrypt.add(new BigInteger("2").multiply(r())).add(r().multiply(Key.PublicKey.x)).mod(Key.PublicKey.N);
    }

    public String decrypt(ArrayList<EncryptMessage> EncryptMessage) {
        StringBuilder message = new StringBuilder();
        for (EncryptMessage encrypt : EncryptMessage) {
            message.append(decrypt(encrypt));
        }
        return message.toString();
    }

    private String decrypt(EncryptMessage encrypt) {
        BigDecimal sum = BigDecimal.ZERO;
        for (int s : Key.PrivateKey.S) {
            sum = sum.add(encrypt.Z.get(s));
        }
        return sum.toBigInteger().and(BigInteger.ONE).xor(encrypt.C.and(BigInteger.ONE)).toString();
    }

    private EncryptMessage enaluate(EncryptMessage encrypt) {
        encrypt.Z.clear();
        int accuracy = (int) (Math.log10(KeySize) + Math.log10(Math.log10(KeySize)));
        for (BigDecimal y : Key.PublicKey.Y) {
            encrypt.Z.add(y.multiply(new BigDecimal(encrypt.C)).setScale(accuracy, BigDecimal.ROUND_DOWN));
        }
        return encrypt;
    }
}
