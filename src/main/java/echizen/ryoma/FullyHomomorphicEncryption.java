package echizen.ryoma;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Random;

public class FullyHomomorphicEncryption {
    private int gamma;
    private int rho;
    private int eta;
    private int tau;
    private BigInteger SecretKey;
    private ArrayList<BigInteger> PublicKey;

    public FullyHomomorphicEncryption() {
        gamma = 26*26*26;
        rho = 26;
        eta = 830;
        tau = 158;
    }

    public FullyHomomorphicEncryption(int gamma, int rho, int eta, int tau) {
        this.gamma = gamma;
        this.rho = rho;
        this.eta = eta;
        this.tau = tau;
    }

    public static void main(String[] args) {
        String mess = "01";
        FullyHomomorphicEncryption obj = new FullyHomomorphicEncryption();
        obj.generateKey();
        ArrayList<BigInteger> encrypt = obj.encrypt(mess);
        System.out.println("dec = " + obj.decrypt(encrypt));
    }

    public void generateKey() {
        PublicKey = new ArrayList<>();
        BigInteger ll = new BigInteger("2").pow(eta - 1);
        BigInteger ul = new BigInteger("2").pow(eta);
        BigInteger r;
        Random rnd = new Random();
        while (true) {
            r = new BigInteger(ul.bitLength(), rnd);
            if ((r.compareTo(ll) == 1 && r.compareTo(ul) == -1) && (r.mod(new BigInteger("2")) != BigInteger.ZERO)) {
                break;
            }
        }
        SecretKey = r;
        BigInteger p = SecretKey;
        ll = BigInteger.ZERO;
        ul = new BigInteger("2").pow(gamma).divide(SecretKey).subtract(BigInteger.ONE);

        ArrayList<BigInteger> qtau = new ArrayList<>();
        for (int i = 0; i <= tau; i++) {
            while (true) {
                r = new BigInteger(ul.bitLength(), rnd);
                if ((r.compareTo(ll) == 1 && r.compareTo(ul) == -1)) {
                    break;
                }
            }
            qtau.add(r);
        }
        Collections.sort(qtau);
        Collections.reverse(qtau);
        if (qtau.get(0).mod(new BigInteger("2")) == BigInteger.ZERO) {
            BigInteger ti = qtau.get(0).add(BigInteger.ONE);
            qtau.set(0, ti);
        }
        ll = BigInteger.ONE;
        ul = new BigInteger("2").pow(rho).subtract(BigInteger.ONE);
        while (true) {
            r = new BigInteger(ul.bitLength(), rnd);
            if ((r.compareTo(ll) == 1 && r.compareTo(ul) == -1)) {
                break;
            }
        }
        BigInteger x0 = qtau.get(0).multiply(p).add(new BigInteger("2").multiply(r));
        PublicKey.add(x0);
        for (int i = 1; i <= tau; i++) {
            while (true) {
                r = new BigInteger(ul.bitLength(), rnd);
                if ((r.compareTo(ll) == 1 && r.compareTo(ul) == -1)) {
                    break;
                }
            }
            BigInteger x1 = qtau.get(i).multiply(p).add((new BigInteger("2").multiply(r)).mod(x0));
            PublicKey.add(x1);
        }
    }

    public ArrayList<BigInteger> encrypt(String bits) {
        ArrayList<BigInteger> enc = new ArrayList<>();
        int subSize = (int) (Math.random() * (double) tau);
        if (subSize == 0) {

            subSize = 1;

        }
        int rn;
        ArrayList<Integer> S = new ArrayList<>();
        for (int i = 0; i < subSize; i++) {
            do {
                rn = (int) (Math.random() * (double) tau);
                if (rn == 0) {
                    rn = 1;
                }
            } while (S.contains(rn));
            S.add(rn);
        }
        BigInteger sum = BigInteger.ZERO;
        for (Integer i : S) {
            sum = sum.add(PublicKey.get(i).mod(PublicKey.get(0)));
        }
        BigInteger ll = BigInteger.ONE;
        BigInteger ul = new BigInteger("2").pow(rho).subtract(BigInteger.ONE);
        Random rnd = new Random();
        BigInteger r;
        while (true) {
            r = new BigInteger(ul.bitLength(), rnd);
            if ((r.compareTo(ll) == 1 && r.compareTo(ul) == -1)) {
                break;
            }
        }
        for (int i = 0; i < bits.length(); i++) {
            String substring = bits.substring(i, i + 1);
            BigInteger m = new BigInteger(substring);
            BigInteger c = m.add(new BigInteger("2").multiply(r)).add(sum);
            enc.add(c);
        }
        return enc;
    }

    public String decrypt(ArrayList<BigInteger> enc) {
        StringBuilder decoded = new StringBuilder();
        for (BigInteger enc1 : enc) {
            BigInteger mod = enc1.mod(SecretKey).mod(new BigInteger("2"));
            decoded.append(mod.toString());
        }
        return decoded.toString();
    }

    public int getGamma() {
        return gamma;
    }

    public void setGamma(int gamma) {
        this.gamma = gamma;
    }

    public int getRho() {
        return rho;
    }

    public void setRho(int rho) {
        this.rho = rho;
    }

    public int getEta() {
        return eta;
    }

    public void setEta(int eta) {
        this.eta = eta;
    }

    public int getTau() {
        return tau;
    }

    public void setTau(int tau) {
        this.tau = tau;
    }

    public ArrayList<BigInteger> getPublicKey() {
        return PublicKey;
    }

    public void setPublicKey(ArrayList<BigInteger> publicKey) {
        PublicKey = publicKey;
    }

    public void setSecretKey(BigInteger secretKey) {
        SecretKey = secretKey;
    }
}