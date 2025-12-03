package utils;

import crypto.rsa.RSAUtil;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Base64;

public class MessageUtil {
    
    /**
     * 组合消息和签名（M || S）
     * 格式：base64(消息长度) + "|" + 消息 + "|SIG|" + base64(签名)
     */
    public static String combineMessageAndSignature(String message, byte[] signature) {
        // 将签名转换为Base64
        String sigBase64 = Base64.getEncoder().encodeToString(signature);
        
        // 添加消息长度前缀，便于解析
        String msgLen = Base64.getEncoder().encodeToString(
            String.valueOf(message.getBytes().length).getBytes()
        );
        
        return msgLen + "|" + message + "|SIG|" + sigBase64;
    }
    
    /**
     * 分离消息和签名
     */
    public static MessageParts separateMessageAndSignature(String combined) 
            throws IllegalArgumentException {
        // 找到最后一个 |SIG| 分隔符
        int sigIndex = combined.lastIndexOf("|SIG|");
        if (sigIndex == -1) {
            throw new IllegalArgumentException("无效的组合消息格式：找不到 |SIG| 分隔符");
        }
        
        String firstPart = combined.substring(0, sigIndex);
        String sigBase64 = combined.substring(sigIndex + 5); // 5 是 "|SIG|" 的长度
        
        // 解析第一部分：长度|消息
        int lenSepIndex = firstPart.indexOf('|');
        if (lenSepIndex == -1) {
            // 如果没有长度前缀，整个就是消息
            String message = firstPart;
            byte[] signature = Base64.getDecoder().decode(sigBase64);
            return new MessageParts(message, signature);
        }
        
        // 有长度前缀的情况
        String lengthBase64 = firstPart.substring(0, lenSepIndex);
        String message = firstPart.substring(lenSepIndex + 1);
        
        // 解码长度（可选，用于验证）
        try {
            byte[] lenBytes = Base64.getDecoder().decode(lengthBase64);
            int expectedLength = Integer.parseInt(new String(lenBytes));
            int actualLength = message.getBytes().length;
            // 可以在这里验证长度，但不强制要求
        } catch (Exception e) {
            // 长度解码失败，忽略长度验证
        }
        
        byte[] signature = Base64.getDecoder().decode(sigBase64);
        return new MessageParts(message, signature);
    }
    
    /**
     * 组合消息、签名并加密
     */
    public static byte[] combineEncrypt(String message, byte[] signature, PublicKey receiverPublicKey) 
            throws Exception {
        String combined = combineMessageAndSignature(message, signature);
        return RSAUtil.encrypt(combined.getBytes("UTF-8"), receiverPublicKey);
    }
    
    /**
     * 解密并分离消息和签名
     */
    public static MessageParts decryptAndSeparate(byte[] encrypted, PrivateKey receiverPrivateKey) 
            throws Exception {
        byte[] decrypted = RSAUtil.decrypt(encrypted, receiverPrivateKey);
        String combined = new String(decrypted, "UTF-8");
        return separateMessageAndSignature(combined);
    }
    
    /**
     * 内部类用于返回消息和签名
     */
    public static class MessageParts {
        public final String message;
        public final byte[] signature;
        
        public MessageParts(String message, byte[] signature) {
            this.message = message;
            this.signature = signature;
        }
    }
}