package echizen.ryoma;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

public class FullHomomorphicEncryption {
    protected KeyPair Key;
    protected int KeySize;

    public KeyPair generateKeyPair(int keySize) {
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
        int k = 4 * KeySize + 2;
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
        int length = KeySize;
        SecureRandom secureRandom = new SecureRandom();
        BigInteger N = Key.PrivateKey.p.multiply(new BigInteger(length, secureRandom));

        Random random = new Random();
        BigInteger integer;
        do {
            integer = new BigInteger(length, random);
        } while (integer.mod(new BigInteger("2")).equals(BigInteger.ZERO));
        BigInteger x = Key.PrivateKey.p.multiply(integer).add(new BigInteger("2").multiply(r()));

        int k = 4 * KeySize + 2;
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

        int accurate = (int) (2 * (2 * KeySize + 3) * Math.log10(2));
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

    protected EncryptMessage encrypt(EncryptMessage encrypt) {
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

    private BigInteger decrypt(BigInteger encrypt) {
        return encrypt.and(BigInteger.ONE).xor(encrypt.divide(Key.PrivateKey.p).and(BigInteger.ONE));
    }

    private EncryptMessage recrypte(EncryptMessage encrypt) {
        return encrypt(new EncryptMessage(recrypte(encrypt.C)));
    }

    private BigInteger recrypte(BigInteger encrypt) {
        return encrypt(decrypt(encrypt));
    }

    public ArrayList<EncryptMessage> xor(ArrayList<EncryptMessage> c1, ArrayList<EncryptMessage> c2) {
        ArrayList<EncryptMessage> result = new ArrayList<>();
        for (int i = 0; i < c1.size(); i++) {
            result.add(xor(c1.get(i), c2.get(i)));
        }
        return result;
    }

    private EncryptMessage xor(EncryptMessage a, EncryptMessage b) {
        return recrypte(encrypt(new EncryptMessage(xor(a.C, b.C))));
    }

    private BigInteger xor(BigInteger a, BigInteger b) {
        return recrypte(a.add(b).mod(Key.PublicKey.N));
    }

    private BigInteger xor(BigInteger a, BigInteger b, BigInteger c) {
        return xor(xor(a, b), c);
    }

    private BigInteger or(BigInteger a, BigInteger b) {
        return recrypte(xor(xor(a, b), and(a, b)));
    }

    public ArrayList<EncryptMessage> and(ArrayList<EncryptMessage> c1, ArrayList<EncryptMessage> c2) {
        ArrayList<EncryptMessage> result = new ArrayList<>();
        for (int i = 0; i < c1.size(); i++) {
            result.add(and(c1.get(i), c2.get(i)));
        }
        return result;
    }

    private EncryptMessage and(EncryptMessage a, EncryptMessage b) {
        return recrypte(encrypt(new EncryptMessage(and(a.C, b.C))));
    }

    private BigInteger and(BigInteger a, BigInteger b) {
        return recrypte(a.multiply(b).mod(Key.PublicKey.N));
    }

    public ArrayList<EncryptMessage> add(ArrayList<EncryptMessage> a, ArrayList<EncryptMessage> b) {
        Collections.reverse(a);
        Collections.reverse(b);
        ArrayList<EncryptMessage> result = new ArrayList<>();
        BigInteger carry = encrypt(BigInteger.ZERO);
        for (int i = 0; i < a.size(); i++) {
            result.add(encrypt(new EncryptMessage(xor(a.get(i).C, b.get(i).C, carry))));
            carry = or(and(a.get(i).C, b.get(i).C), and(carry, xor(a.get(i).C, b.get(i).C)));
        }
        Collections.reverse(result);
        return result;
    }
}
