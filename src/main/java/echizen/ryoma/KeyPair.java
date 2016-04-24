package echizen.ryoma;

import com.google.gson.Gson;
import sun.misc.BASE64Encoder;

import java.io.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

public class KeyPair {
    protected PrivateKey privateKey;
    protected PublicKey publicKey;

    private int privateKeySize;
    private int publicKeySize;
    private int noiseSize;

    public KeyPair(int keySize) {
        privateKey = new PrivateKey();
        publicKey = new PublicKey();
        privateKeySize = keySize;
        publicKeySize = 4 * keySize + 2;
        noiseSize = (int) Math.pow(keySize, 0.25) + 1;
    }

    public KeyPair(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        privateKeySize = privateKey.p.bitCount();
        publicKeySize = 4 * privateKeySize + 2;
        noiseSize = (int) Math.pow(privateKeySize, 0.25) + 1;
    }

    private BigInteger noise() {
        int length = noiseSize;
        Random random = new Random();
        return new BigInteger(length, random);
    }

    public KeyPair generate() {
        privateKey = generatePrivateKey();
        publicKey = generatePublicKey();

        publicKey.S = new ArrayList<>();
        for (int i = 0; i < publicKeySize; i++) {
            BigInteger integer = BigInteger.ZERO;
            if (publicKey.S.contains(i)) {
                integer = BigInteger.ONE;
            }
            publicKey.S.add(encrypt(integer));
        }
        return this;
    }

    private BigInteger encrypt(BigInteger encrypt) {
        return encrypt.add(new BigInteger("2").multiply(noise())).add(noise().multiply(publicKey.x)).mod(publicKey.N);
    }

    private PrivateKey generatePrivateKey() {
        SecureRandom secureRandom = new SecureRandom();
        BigInteger p = new BigInteger(privateKeySize, 100, secureRandom);

        Set<Integer> S = new HashSet<>();
        Random random = new Random();
        int count = (int) Math.sqrt(privateKeySize);
        for (int i = 0; i < count - 1; i++) {
            int number = random.nextInt(publicKeySize - 1);
            if (!S.contains(number)) {
                S.add(number);
            } else {
                i--;
            }
        }
        S.add(publicKeySize - 1);
        return new PrivateKey(p, S);
    }

    private PublicKey generatePublicKey() {
        int length = privateKeySize;
        SecureRandom secureRandom = new SecureRandom();
        BigInteger N = privateKey.p.multiply(new BigInteger(length, secureRandom));

        Random random = new Random();
        BigInteger integer;
        do {
            integer = new BigInteger(length, random);
        } while (integer.mod(new BigInteger("2")).equals(BigInteger.ZERO));
        BigInteger x = privateKey.p.multiply(integer).add(new BigInteger("2").multiply(r()));

        BigInteger K = new BigInteger("2").pow(publicKeySize).divide(privateKey.p);
        ArrayList<BigInteger> U = new ArrayList<>();

        BigInteger u;
        for (int i = 0; i < publicKeySize - 1; i++) {
            do {
                u = new BigInteger(publicKeySize + 1, random);
            } while (U.contains(u));
            U.add(u);
        }
        U.add(BigInteger.ZERO);
        BigInteger sum = BigInteger.ZERO;
        for (int s : privateKey.S) {
            sum = sum.add(U.get(s));
        }
        u = K.subtract(sum).mod(new BigInteger("2").pow(publicKeySize + 1));
        U.set(U.size() - 1, u);

        int accurate = (int) (2 * (4 * privateKeySize + 2) * Math.log10(2));
        BigInteger Mod = new BigInteger("2").pow(publicKeySize);
        publicKey.Y = new ArrayList<>();
        for (int i = 0; i < publicKeySize; i++) {
            publicKey.Y.add(new BigDecimal(U.get(i)).divide(new BigDecimal(Mod), accurate, BigDecimal.ROUND_DOWN));
        }
        return new PublicKey(N, x, publicKey.Y);
    }

    private BigInteger r() {
        int length = (int) Math.pow(privateKeySize, 0.25) + 1;
        Random random = new Random();
        return new BigInteger(length, random);
    }


    public void save(String PrivateKeyFileName, String PublicKeyFileName) throws IOException {
        File file = new File(PrivateKeyFileName);
        if (file.exists()) {
            file.delete();
        } else {
            if (!file.getParentFile().exists()) {
                file.getParentFile().mkdirs();
            }
            file.createNewFile();
        }
        Writer writer = new OutputStreamWriter(new FileOutputStream(file), "UTF-8");
        writer.write("-----BEGIN FHE PRIVATE KEY-----\n");
        writer.write((new BASE64Encoder()).encode((new Gson()).toJson(privateKey).toString().getBytes()));
        writer.write("\n-----END FHE PRIVATE KEY-----\n");
        writer.close();

        file = new File(PublicKeyFileName);
        if (file.exists()) {
            file.delete();
        } else {
            if (!file.getParentFile().exists()) {
                file.getParentFile().mkdirs();
            }
            file.createNewFile();
        }
        writer = new OutputStreamWriter(new FileOutputStream(file), "UTF-8");
        writer.write("-----BEGIN FHE PUBLIC KEY-----\n");
        writer.write((new BASE64Encoder()).encode((new Gson()).toJson(publicKey).toString().getBytes()));
        writer.write("\n-----END FHE PUBLIC KEY-----\n");
        writer.close();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
