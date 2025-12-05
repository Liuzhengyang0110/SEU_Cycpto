package crypto.hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashUtil {
    
    // 原有的字符串方法保持不变
    public static String md5(String input) {
        return hash(input, "MD5");
    }
    
    public static String sha256(String input) {
        return hash(input, "SHA-256");
    }
    
    // 新增：字节数组方法
    public static String md5(byte[] input) {
        return hash(input, "MD5");
    }
    
    public static String sha256(byte[] input) {
        return hash(input, "SHA-256");
    }
    
    // 字符串哈希的私有方法
    private static String hash(String input, String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hashBytes = digest.digest(input.getBytes("UTF-8"));
            return bytesToHex(hashBytes);
        } catch (Exception e) {
            throw new RuntimeException("Hash计算失败: " + e.getMessage(), e);
        }
    }
    
    // 字节数组哈希的私有方法
    private static String hash(byte[] input, String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hashBytes = digest.digest(input);
            return bytesToHex(hashBytes);
        } catch (Exception e) {
            throw new RuntimeException("Hash计算失败: " + e.getMessage(), e);
        }
    }
    
    // 字节数组转十六进制字符串
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}