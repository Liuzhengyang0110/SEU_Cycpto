package crypto.hash;

import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;

public class HashUtil {

    // 字符串 MD5
    public static String md5(String input) {
        return hashString(input, "MD5");
    }

    // 字符串 SHA-256
    public static String sha256(String input) {
        return hashString(input, "SHA-256");
    }

    private static String hashString(String input, String algo) {
        try {
            MessageDigest md = MessageDigest.getInstance(algo);
            byte[] result = md.digest(input.getBytes("UTF-8"));
            return bytesToHex(result);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // 文件 MD5
    public static String md5File(File file) {
        return hashFile(file, "MD5");
    }

    // 文件 SHA-256
    public static String sha256File(File file) {
        return hashFile(file, "SHA-256");
    }

    private static String hashFile(File file, String algo) {
        try {
            MessageDigest md = MessageDigest.getInstance(algo);
            FileInputStream fis = new FileInputStream(file);

            byte[] buffer = new byte[4096];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                md.update(buffer, 0, len);
            }
            fis.close();

            return bytesToHex(md.digest());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // byte[] 转 hex 字符串
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
