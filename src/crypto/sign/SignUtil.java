package crypto.sign;

import java.security.*;
import javax.crypto.Cipher;

public class SignUtil {

    // 用私钥对 hash 签名
    public static byte[] sign(String hash, PrivateKey key) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(hash.getBytes("UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // 用公钥验证：解密得到 hash，再比较
    public static boolean verify(String originalHash, byte[] signature, PublicKey key) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = cipher.doFinal(signature);
            String result = new String(decrypted, "UTF-8");
            return originalHash.equals(result);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
