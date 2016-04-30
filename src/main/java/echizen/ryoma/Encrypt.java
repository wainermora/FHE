package echizen.ryoma;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

public class Encrypt {
    private PublicKey PublicKey;
    private int PublicKeySize;
    private int PrivateKeySize;
    private int NoiseSize;

    public Encrypt(PublicKey publicKey) {
        PublicKey = publicKey;
        PublicKeySize = PublicKey.S.size();
        PrivateKeySize = (PublicKeySize - 2) / 4;
        NoiseSize = (int) Math.sqrt(PrivateKeySize) + 1;
    }

    private BigInteger noise() {
        int length = NoiseSize;
        Random random = new Random();
        return new BigInteger(length, random);
    }

    public ArrayList<EncryptMessage> encrypt(String message) {
        ArrayList<EncryptMessage> EncryptMessage = new ArrayList<>();
        for (int i = 0; i < message.length(); i++) {
            EncryptMessage encrypt = new EncryptMessage();
            encrypt.C = new BigInteger(String.valueOf(message.charAt(i))).add(new BigInteger("2").multiply(noise())).add(noise().multiply(PublicKey.x)).mod(PublicKey.N);
            encrypt = encrypt(encrypt);
            EncryptMessage.add(encrypt);
        }
        return EncryptMessage;
    }

    private EncryptMessage encrypt(EncryptMessage encrypt) {
        encrypt.Z.clear();
        int accuracy = (int) (PrivateKeySize * Math.log10(2) + 3);
        for (BigDecimal y : PublicKey.Y) {
            BigDecimal decimal = y.multiply(new BigDecimal(encrypt.C));
            BigInteger integer = decimal.toBigInteger();
            decimal = decimal.subtract(new BigDecimal(integer)).setScale(accuracy, BigDecimal.ROUND_DOWN);
            integer = integer.mod(new BigInteger("2"));
            decimal = decimal.add(new BigDecimal(integer)).remainder(new BigDecimal("2"));
            encrypt.Z.add(decimal);
        }
        return encrypt;
    }

    public EncryptMessage recrypt(EncryptMessage encrypt) {
        int accuracy = PrivateKeySize + 3;
        Integer[][] A = new Integer[encrypt.Z.size()][accuracy];

        for (int i = 0; i < encrypt.Z.size(); i++) {
            BigDecimal z = encrypt.Z.get(i);
            A[i][0] = z.toBigInteger().and(BigInteger.ONE).intValue();
            z = z.subtract(new BigDecimal(z.toBigInteger()));
            for (int j = 1; j < accuracy; j++) {
                z = z.multiply(new BigDecimal("2"));
                A[i][j] = z.intValue();
                z = z.subtract(new BigDecimal(z.intValue()));
            }
        }

        BigInteger[][] B = new BigInteger[encrypt.Z.size()][accuracy];
        for (int i = 0; i < encrypt.Z.size(); i++) {
            for (int j = 0; j < accuracy; j++) {
                B[i][j] = PublicKey.S.get(i).multiply(new BigInteger(A[i][j].toString()));
            }
        }

        int v = (int) (Math.log(PrivateKeySize) / Math.log(2)) + 1;
        BigInteger[][] D = new BigInteger[accuracy][accuracy];
        for (int i = 0; i < accuracy; i++) {
            for (int j = 0; j < accuracy; j++) {
                D[i][j] = BigInteger.ZERO;
            }
        }
        BigInteger[] d = new BigInteger[accuracy];

        for (int i = accuracy - 1; i >= 0; i--) {
            ArrayList<BigInteger> b = new ArrayList<>();
            for (int j = 0; j < encrypt.Z.size(); j++) {
                b.add(B[j][i]);
            }

            for (int k = accuracy - 1 - i >= v ? v : (accuracy - 1 - i); k > 0; k--) {
                b.add(D[i + k][i]);
            }
            d[i] = e(1, b);
            for (int j = 1; i - j >= 0 && j < v; j++) {
                D[i][i - j] = e((int) Math.pow(2, j), b);
            }
        }
        return encrypt(new EncryptMessage(encrypt.C.add(d[0].add(d[1]).mod(PublicKey.N)).mod(PublicKey.N)));
    }

    private BigInteger e(int i, ArrayList<BigInteger> b) {
        BigInteger sum = BigInteger.ZERO;
        for (int j = 0; j < b.size() - i; j++) {
            BigInteger product = BigInteger.ONE;
            for (int k = 0; k < i; k++) {
                product = product.multiply(b.get(j + k)).mod(PublicKey.N);
            }
            sum = sum.add(product).mod(PublicKey.N);
        }
        return sum;
    }

    public ArrayList<EncryptMessage> xor(ArrayList<EncryptMessage> c1, ArrayList<EncryptMessage> c2) {
        ArrayList<EncryptMessage> result = new ArrayList<>();
        for (int i = 0; i < c1.size(); i++) {
            result.add(xor(c1.get(i), c2.get(i)));
        }
        return result;
    }

    private EncryptMessage xor(EncryptMessage a, EncryptMessage b) {
        return recrypt(encrypt(new EncryptMessage(xor(a.C, b.C))));
    }

    private BigInteger xor(BigInteger a, BigInteger b) {
        return a.add(b).mod(PublicKey.N);
    }

    private EncryptMessage or(EncryptMessage a, EncryptMessage b) {
        return xor(xor(a, b), and(a, b));
    }

    public ArrayList<EncryptMessage> or(ArrayList<EncryptMessage> c1, ArrayList<EncryptMessage> c2) {
        ArrayList<EncryptMessage> result = new ArrayList<>();
        for (int i = 0; i < c1.size(); i++) {
            result.add(or(c1.get(i), c2.get(i)));
        }
        return result;
    }

    public ArrayList<EncryptMessage> and(ArrayList<EncryptMessage> c1, ArrayList<EncryptMessage> c2) {
        ArrayList<EncryptMessage> result = new ArrayList<>();
        for (int i = 0; i < c1.size(); i++) {
            result.add(and(c1.get(i), c2.get(i)));
        }
        return result;
    }

    private EncryptMessage and(EncryptMessage a, EncryptMessage b) {
        return recrypt(encrypt(new EncryptMessage(and(a.C, b.C))));
    }

    private BigInteger and(BigInteger a, BigInteger b) {
        return a.multiply(b).mod(PublicKey.N);
    }
}
