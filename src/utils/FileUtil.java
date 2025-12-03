package utils;

import java.io.File;
import java.nio.file.Files;

public class FileUtil {

    // 读文件 bytes
    public static byte[] readFile(File file) {
        try {
            return Files.readAllBytes(file.toPath());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // 保存文件
    public static boolean saveFile(byte[] data, File file) {
        try {
            Files.write(file.toPath(), data);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
