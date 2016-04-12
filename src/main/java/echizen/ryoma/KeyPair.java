package echizen.ryoma;

import com.google.gson.Gson;
import sun.misc.BASE64Encoder;

import java.io.*;

public class KeyPair {
    public PrivateKey PrivateKey;
    public PublicKey PublicKey;

    public KeyPair() {
        PrivateKey = new PrivateKey();
        PublicKey = new PublicKey();
    }

    public KeyPair(PrivateKey privateKey, PublicKey publicKey) {
        PrivateKey = privateKey;
        PublicKey = publicKey;
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
    }
}
