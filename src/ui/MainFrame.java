package ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.File;

import crypto.hash.HashUtil;
import crypto.symmetric.SymmetricCrypto;
import crypto.rsa.RSAUtil;
import crypto.sign.SignUtil;
import utils.FileUtil;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class MainFrame extends JFrame {

    // RSA key
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public MainFrame() {
        setTitle("密码学课程大作业 - Crypto System");
        setSize(900, 650);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel main = new JPanel();
        main.setLayout(new BorderLayout());

        //---------------------------------------
        // 顶部标题
        //---------------------------------------
        JLabel title = new JLabel("密码学课程大作业 - 加密 / 解密 / 签名 / 验证系统", JLabel.CENTER);
        title.setFont(new Font("宋体", Font.BOLD, 22));
        main.add(title, BorderLayout.NORTH);

        //---------------------------------------
        // 中间区域（左右分栏）
        //---------------------------------------
        JPanel center = new JPanel(new GridLayout(1, 2));

        // 左侧面板（文本输入）
        JPanel left = new JPanel();
        left.setLayout(new GridLayout(10, 1, 5, 5));

        JTextArea inputArea = new JTextArea(5, 20);
        JTextArea outputArea = new JTextArea(5, 20);
        JTextArea signatureArea = new JTextArea(5, 20);

        inputArea.setBorder(BorderFactory.createTitledBorder("输入明文 / 文本"));
        outputArea.setBorder(BorderFactory.createTitledBorder("输出结果"));
        signatureArea.setBorder(BorderFactory.createTitledBorder("签名"));

        left.add(new JScrollPane(inputArea));
        left.add(new JScrollPane(outputArea));
        left.add(new JScrollPane(signatureArea));

        // 右侧功能区
        JPanel right = new JPanel();
        right.setLayout(new GridLayout(15, 1, 5, 5));

        //---------------------------------------
        // 算法选择
        //---------------------------------------
        String[] hashOptions = {"MD5", "SHA-256"};
        String[] symmetricOptions = {"AES", "DES"};

        JComboBox<String> hashBox = new JComboBox<>(hashOptions);
        JComboBox<String> symBox = new JComboBox<>(symmetricOptions);

        JTextField keyField = new JTextField();
        keyField.setBorder(BorderFactory.createTitledBorder("对称密钥（可自动生成）"));

        JButton genKeyBtn = new JButton("生成对称密钥");

        JButton rsaBtn = new JButton("生成 RSA 密钥对（2048 位）");

        //---------------------------------------
        // 按钮：Hash、加密、解密、签名、验证
        //---------------------------------------
        JButton hashBtn = new JButton("计算 Hash");
        JButton encBtn = new JButton("对称加密");
        JButton decBtn = new JButton("对称解密");
        JButton signBtn = new JButton("私钥签名");
        JButton verifyBtn = new JButton("公钥验证签名");

        //---------------------------------------
        // 文件选择
        //---------------------------------------
        JButton fileEncBtn = new JButton("文件加密");
        JButton fileDecBtn = new JButton("文件解密");

        //---------------------------------------
        // 添加按钮到右侧面板
        //---------------------------------------
        right.add(new JLabel("选择 Hash 算法："));
        right.add(hashBox);

        right.add(new JLabel("选择对称加密算法："));
        right.add(symBox);

        right.add(keyField);
        right.add(genKeyBtn);
        right.add(rsaBtn);

        right.add(hashBtn);
        right.add(encBtn);
        right.add(decBtn);
        right.add(signBtn);
        right.add(verifyBtn);

        right.add(fileEncBtn);
        right.add(fileDecBtn);

        //---------------------------------------
        // 按钮事件绑定
        //---------------------------------------

        // 生成对称密钥
        genKeyBtn.addActionListener(e -> {
            String type = (String) symBox.getSelectedItem();
            String key = null;
            if ("AES".equals(type)) key = SymmetricCrypto.generateAESKey();
            else key = SymmetricCrypto.generateDESKey();

            keyField.setText(key);
        });

        // Hash 计算
        hashBtn.addActionListener(e -> {
            String text = inputArea.getText();
            if (text.isEmpty()) return;

            String algo = (String) hashBox.getSelectedItem();
            String hash;
            if ("MD5".equals(algo))
                hash = HashUtil.md5(text);
            else
                hash = HashUtil.sha256(text);

            outputArea.setText(hash);
        });

        // 生成 RSA 密钥对
        rsaBtn.addActionListener(e -> {
            KeyPair kp = RSAUtil.generateKeyPair(2048);
            publicKey = kp.getPublic();
            privateKey = kp.getPrivate();

            JOptionPane.showMessageDialog(this, "RSA 密钥对生成成功！");
        });

        // 对称加密
        encBtn.addActionListener(e -> {
            try {
                String text = inputArea.getText();
                String key = keyField.getText();
                if (text.isEmpty() || key.isEmpty()) return;

                byte[] data = text.getBytes("UTF-8");
                byte[] cipher = null;

                String algo = (String) symBox.getSelectedItem();
                if ("AES".equals(algo))
                    cipher = SymmetricCrypto.encryptAES(data, key);
                else
                    cipher = SymmetricCrypto.encryptDES(data, key);

                outputArea.setText(bytesToHex(cipher));
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        });

        // 对称解密
        decBtn.addActionListener(e -> {
            try {
                String hex = inputArea.getText();
                String key = keyField.getText();

                if (hex.isEmpty() || key.isEmpty()) return;

                byte[] data = hexToBytes(hex);
                byte[] plain = null;

                String algo = (String) symBox.getSelectedItem();
                if ("AES".equals(algo))
                    plain = SymmetricCrypto.decryptAES(data, key);
                else
                    plain = SymmetricCrypto.decryptDES(data, key);

                outputArea.setText(new String(plain, "UTF-8"));
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        });

        // 私钥签名
        signBtn.addActionListener(e -> {
            if (privateKey == null) {
                JOptionPane.showMessageDialog(this, "请先生成 RSA 密钥对！");
                return;
            }

            String text = inputArea.getText();
            if (text.isEmpty()) return;

            String algo = (String) hashBox.getSelectedItem();
            String hash = ("MD5".equals(algo)) ? HashUtil.md5(text) : HashUtil.sha256(text);

            byte[] sign = SignUtil.sign(hash, privateKey);
            signatureArea.setText(bytesToHex(sign));
        });

        // 公钥验证签名
        verifyBtn.addActionListener(e -> {
            if (publicKey == null) {
                JOptionPane.showMessageDialog(this, "请先生成 RSA 密钥对！");
                return;
            }

            String text = inputArea.getText();
            String signHex = signatureArea.getText();
            if (text.isEmpty() || signHex.isEmpty()) return;

            String algo = (String) hashBox.getSelectedItem();
            String hash = ("MD5".equals(algo)) ? HashUtil.md5(text) : HashUtil.sha256(text);

            boolean ok = SignUtil.verify(hash, hexToBytes(signHex), publicKey);
            outputArea.setText(ok ? "签名验证成功 ✔" : "签名验证失败 ✘");
        });

        // 文件加密
        fileEncBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                File file = chooser.getSelectedFile();
                byte[] data = FileUtil.readFile(file);

                String key = keyField.getText();
                if (key.isEmpty()) {
                    JOptionPane.showMessageDialog(this, "请先生成对称密钥！");
                    return;
                }

                byte[] cipher;
                if ("AES".equals(symBox.getSelectedItem()))
                    cipher = SymmetricCrypto.encryptAES(data, key);
                else
                    cipher = SymmetricCrypto.encryptDES(data, key);

                File save = new File(file.getAbsolutePath() + ".enc");
                FileUtil.saveFile(cipher, save);
                JOptionPane.showMessageDialog(this, "文件已加密: " + save.getName());
            }
        });

        // 文件解密
        fileDecBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                File file = chooser.getSelectedFile();
                byte[] data = FileUtil.readFile(file);

                String key = keyField.getText();
                if (key.isEmpty()) {
                    JOptionPane.showMessageDialog(this, "请先生成对称密钥！");
                    return;
                }

                byte[] plain;
                if ("AES".equals(symBox.getSelectedItem()))
                    plain = SymmetricCrypto.decryptAES(data, key);
                else
                    plain = SymmetricCrypto.decryptDES(data, key);

                File save = new File(file.getAbsolutePath() + ".dec");
                FileUtil.saveFile(plain, save);
                JOptionPane.showMessageDialog(this, "文件已解密: " + save.getName());
            }
        });

        //---------------------------------------
        // 加入面板
        //---------------------------------------
        center.add(left);
        center.add(right);
        main.add(center, BorderLayout.CENTER);

        setContentPane(main);
        setVisible(true);
    }


    //---------------------------------------
    // 工具函数：Hex ↔ Bytes
    //---------------------------------------
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length() / 2;
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++)
            result[i] = (byte) Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        return result;
    }
}

