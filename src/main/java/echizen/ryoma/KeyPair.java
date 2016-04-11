package echizen.ryoma;

import com.google.gson.Gson;
import sun.misc.BASE64Encoder;

import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;

public class KeyPair {
    private BigInteger PrivateKey;
    private ArrayList<BigInteger> PublicKey;

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
        writer.write((new BASE64Encoder()).encode((new Gson()).toJson(PrivateKey).toString().getBytes()));
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
        writer.write((new BASE64Encoder()).encode((new Gson()).toJson(PublicKey).toString().getBytes()));
        writer.write("\n-----END FHE PUBLIC KEY-----\n");
        writer.close();
    }

    public KeyPair() {
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
        writer.write((new BASE64Encoder()).encode((new Gson()).toJson(PrivateKey).toString().getBytes()));
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
        writer.write((new BASE64Encoder()).encode((new Gson()).toJson(PublicKey).toString().getBytes()));
        writer.write("\n-----END FHE PUBLIC KEY-----\n");
        writer.close();
    }    public KeyPair(BigInteger secretKey, ArrayList<BigInteger> publicKey) {
        PrivateKey = secretKey;
        PublicKey = publicKey;
    }

    public BigInteger getPrivateKey() {
        return PrivateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        PrivateKey = privateKey;
    }

    public ArrayList<BigInteger> getPublicKey() {
        return PublicKey;
    }

    public void setPublicKey(ArrayList<BigInteger> publicKey) {
        PublicKey = publicKey;
    }
}
