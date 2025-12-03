package crypto.symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricCrypto {

    // 生成 AES 密钥（128位）
    public static String generateAESKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey key = kg.generateKey();
            return bytesToHex(key.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // AES 加密
    public static byte[] encryptAES(byte[] data, String hexKey) {
        try {
            SecretKeySpec key = new SecretKeySpec(hexToBytes(hexKey), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // AES 解密
    public static byte[] decryptAES(byte[] data, String hexKey) {
        try {
            SecretKeySpec key = new SecretKeySpec(hexToBytes(hexKey), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // 生成 DES 密钥（56位）
    public static String generateDESKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("DES");
            kg.init(56);
            SecretKey key = kg.generateKey();
            return bytesToHex(key.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // DES 加密
    public static byte[] encryptDES(byte[] data, String hexKey) {
        try {
            SecretKeySpec key = new SecretKeySpec(hexToBytes(hexKey), "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // DES 解密
    public static byte[] decryptDES(byte[] data, String hexKey) {
        try {
            SecretKeySpec key = new SecretKeySpec(hexToBytes(hexKey), "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    //-------------------- 工具函数 ------------------------

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length() / 2;
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            result[i] = (byte) Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        }
        return result;
    }
}
