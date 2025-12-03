package ui;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import crypto.hash.HashUtil;
import crypto.symmetric.SymmetricCrypto;
import crypto.rsa.RSAUtil;
import crypto.sign.SignUtil;
import utils.FileUtil;

public class MainFrame extends JFrame {
    
    // 密钥对
    private PrivateKey privateKeyA;
    private PublicKey publicKeyA;
    private PrivateKey privateKeyB;
    private PublicKey publicKeyB;
    
    // 文本区域
    private JTextArea inputArea;
    private JTextArea outputArea;
    private JTextArea signatureArea;
    private JTextArea pubKeyAText;
    private JTextArea privKeyAText;
    private JTextArea pubKeyBText;
    private JTextArea privKeyBText;
    
    // 组合框
    private JComboBox<String> hashBox;
    private JComboBox<String> symBox;
    
    // 输入框
    private JTextField keyField;
    
    public MainFrame() {
        setTitle("密码学课程大作业 - 加密/解密/签名/验证系统");
        setSize(1100, 700);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        
        // 创建主面板
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        // 顶部标题
        JLabel title = new JLabel("密码学课程大作业 - 加密/解密/签名/验证系统", JLabel.CENTER);
        title.setFont(new Font("宋体", Font.BOLD, 22));
        title.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0));
        mainPanel.add(title, BorderLayout.NORTH);
        
        // 创建选项卡
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // 选项卡1: 基础功能
        tabbedPane.addTab("基础功能", createBasicPanel());
        
        // 选项卡2: 完整通信流程
        tabbedPane.addTab("完整流程", createFlowPanel());
        
        // 选项卡3: 密钥管理
        tabbedPane.addTab("密钥管理", createKeyPanel());
        
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
        
        // 底部状态栏
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusPanel.setBorder(BorderFactory.createEtchedBorder());
        JLabel statusLabel = new JLabel("就绪");
        statusLabel.setFont(new Font("宋体", Font.PLAIN, 12));
        statusPanel.add(statusLabel);
        mainPanel.add(statusPanel, BorderLayout.SOUTH);
        
        setContentPane(mainPanel);
        setVisible(true);
    }
    
    /**
     * 创建基础功能面板
     */
    private JPanel createBasicPanel() {
        JPanel panel = new JPanel(new GridLayout(1, 2, 10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 左侧：输入输出区域
        JPanel leftPanel = new JPanel(new BorderLayout(5, 5));
        
        // 输入区域
        JPanel inputPanel = new JPanel(new BorderLayout());
        inputArea = new JTextArea(8, 30);
        inputArea.setLineWrap(true);
        JScrollPane inputScroll = new JScrollPane(inputArea);
        inputScroll.setBorder(BorderFactory.createTitledBorder("输入明文/文本"));
        inputPanel.add(inputScroll, BorderLayout.CENTER);
        
        // 输出区域
        JPanel outputPanel = new JPanel(new BorderLayout());
        outputArea = new JTextArea(8, 30);
        outputArea.setLineWrap(true);
        outputArea.setEditable(false);
        JScrollPane outputScroll = new JScrollPane(outputArea);
        outputScroll.setBorder(BorderFactory.createTitledBorder("输出结果"));
        outputPanel.add(outputScroll, BorderLayout.CENTER);
        
        // 签名区域
        JPanel signaturePanel = new JPanel(new BorderLayout());
        signatureArea = new JTextArea(4, 30);
        signatureArea.setLineWrap(true);
        JScrollPane signatureScroll = new JScrollPane(signatureArea);
        signatureScroll.setBorder(BorderFactory.createTitledBorder("数字签名"));
        signaturePanel.add(signatureScroll, BorderLayout.CENTER);
        
        leftPanel.add(inputPanel, BorderLayout.NORTH);
        leftPanel.add(outputPanel, BorderLayout.CENTER);
        leftPanel.add(signaturePanel, BorderLayout.SOUTH);
        
        // 右侧：功能按钮区域
        JPanel rightPanel = new JPanel();
        rightPanel.setLayout(new BoxLayout(rightPanel, BoxLayout.Y_AXIS));
        rightPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
        
        // 算法选择
        JPanel algoPanel = new JPanel(new GridLayout(4, 2, 5, 5));
        algoPanel.setBorder(BorderFactory.createTitledBorder("算法选择"));
        
        algoPanel.add(new JLabel("Hash算法:"));
        hashBox = new JComboBox<>(new String[]{"SHA-256", "MD5"});
        algoPanel.add(hashBox);
        
        algoPanel.add(new JLabel("对称加密:"));
        symBox = new JComboBox<>(new String[]{"AES", "DES"});
        algoPanel.add(symBox);
        
        algoPanel.add(new JLabel("对称密钥:"));
        JPanel keyPanel = new JPanel(new BorderLayout());
        keyField = new JTextField();
        JButton genKeyBtn = new JButton("生成");
        keyPanel.add(keyField, BorderLayout.CENTER);
        keyPanel.add(genKeyBtn, BorderLayout.EAST);
        algoPanel.add(keyPanel);
        
        rightPanel.add(algoPanel);
        rightPanel.add(Box.createVerticalStrut(10));
        
        // 生成密钥对按钮
        JPanel rsaKeyPanel = new JPanel(new GridLayout(2, 1, 5, 5));
        rsaKeyPanel.setBorder(BorderFactory.createTitledBorder("RSA密钥对"));
        
        JButton genKeyABtn = new JButton("生成 A 的密钥对");
        JButton genKeyBBtn = new JButton("生成 B 的密钥对");
        
        rsaKeyPanel.add(genKeyABtn);
        rsaKeyPanel.add(genKeyBBtn);
        
        rightPanel.add(rsaKeyPanel);
        rightPanel.add(Box.createVerticalStrut(10));
        
        // Hash功能
        JPanel hashPanel = new JPanel(new GridLayout(1, 2, 5, 5));
        hashPanel.setBorder(BorderFactory.createTitledBorder("Hash计算"));
        
        JButton hashBtn = new JButton("计算Hash");
        JButton fileHashBtn = new JButton("文件Hash");
        
        hashPanel.add(hashBtn);
        hashPanel.add(fileHashBtn);
        
        rightPanel.add(hashPanel);
        rightPanel.add(Box.createVerticalStrut(10));
        
        // 对称加密功能
        JPanel symPanel = new JPanel(new GridLayout(2, 2, 5, 5));
        symPanel.setBorder(BorderFactory.createTitledBorder("对称加密"));
        
        JButton encBtn = new JButton("加密文本");
        JButton decBtn = new JButton("解密文本");
        JButton fileEncBtn = new JButton("加密文件");
        JButton fileDecBtn = new JButton("解密文件");
        
        symPanel.add(encBtn);
        symPanel.add(decBtn);
        symPanel.add(fileEncBtn);
        symPanel.add(fileDecBtn);
        
        rightPanel.add(symPanel);
        rightPanel.add(Box.createVerticalStrut(10));
        
        // 数字签名功能
        JPanel signPanel = new JPanel(new GridLayout(2, 2, 5, 5));
        signPanel.setBorder(BorderFactory.createTitledBorder("数字签名"));
        
        JButton signBtn = new JButton("A签名");
        JButton verifyBtn = new JButton("验证签名");
        JButton fileSignBtn = new JButton("文件签名");
        JButton fileVerifyBtn = new JButton("验证文件签名");
        
        signPanel.add(signBtn);
        signPanel.add(verifyBtn);
        signPanel.add(fileSignBtn);
        signPanel.add(fileVerifyBtn);
        
        rightPanel.add(signPanel);
        
        // 添加事件监听器
        setupBasicEventListeners(genKeyBtn, genKeyABtn, genKeyBBtn, hashBtn, 
                                fileHashBtn, encBtn, decBtn, fileEncBtn, 
                                fileDecBtn, signBtn, verifyBtn, fileSignBtn, fileVerifyBtn);
        
        panel.add(leftPanel);
        panel.add(rightPanel);
        
        return panel;
    }
    
    /**
     * 创建完整流程面板
     */
    private JPanel createFlowPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 流程图说明
        JTextArea flowDesc = new JTextArea(
            "完整通信流程说明：\n" +
            "1. A用自己的私钥对消息签名\n" +
            "2. B用A的公钥验证签名，确认消息来自A\n" +
            "3. A用B的公钥加密消息\n" +
            "4. B用自己的私钥解密消息\n" +
            "\n这样可以实现：身份认证 + 保密传输"
        );
        flowDesc.setEditable(false);
        flowDesc.setFont(new Font("宋体", Font.PLAIN, 14));
        flowDesc.setBackground(new Color(240, 240, 240));
        flowDesc.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        panel.add(flowDesc);
        panel.add(Box.createVerticalStrut(20));
        
        // 流程步骤面板
        JPanel stepsPanel = new JPanel(new GridLayout(6, 1, 10, 10));
        
        // 步骤1: A签名
        JPanel step1Panel = new JPanel(new BorderLayout());
        JButton step1Btn = new JButton("步骤1: A对消息签名");
        step1Btn.setBackground(new Color(200, 230, 255));
        JTextArea step1Result = new JTextArea(2, 40);
        step1Result.setEditable(false);
        step1Result.setBorder(BorderFactory.createTitledBorder("签名结果"));
        
        step1Btn.addActionListener(e -> {
            if (privateKeyA == null) {
                JOptionPane.showMessageDialog(this, "请先生成A的密钥对！");
                return;
            }
            String message = inputArea.getText();
            if (message.isEmpty()) {
                JOptionPane.showMessageDialog(this, "请输入消息！");
                return;
            }
            
            // A用私钥签名
            String hash = HashUtil.sha256(message);
            byte[] signature = SignUtil.sign(hash, privateKeyA);
            String signatureHex = bytesToHex(signature);
            
            step1Result.setText("签名（Hex）: " + signatureHex.substring(0, Math.min(100, signatureHex.length())) + "...");
            signatureArea.setText(signatureHex);
            outputArea.setText("✓ A已用私钥对消息完成签名");
        });
        
        step1Panel.add(step1Btn, BorderLayout.NORTH);
        step1Panel.add(new JScrollPane(step1Result), BorderLayout.CENTER);
        
        // 步骤2: B验证签名
        JPanel step2Panel = new JPanel(new BorderLayout());
        JButton step2Btn = new JButton("步骤2: B验证A的签名");
        step2Btn.setBackground(new Color(200, 255, 230));
        JTextArea step2Result = new JTextArea(2, 40);
        step2Result.setEditable(false);
        step2Result.setBorder(BorderFactory.createTitledBorder("验证结果"));
        
        step2Btn.addActionListener(e -> {
            if (publicKeyA == null) {
                JOptionPane.showMessageDialog(this, "请先生成A的密钥对！");
                return;
            }
            
            String message = inputArea.getText();
            String signatureHex = signatureArea.getText();
            if (message.isEmpty() || signatureHex.isEmpty()) {
                JOptionPane.showMessageDialog(this, "请先完成步骤1的签名！");
                return;
            }
            
            // B用A的公钥验证
            String hash = HashUtil.sha256(message);
            boolean verified = SignUtil.verify(hash, hexToBytes(signatureHex), publicKeyA);
            
            step2Result.setText(verified ? 
                "✓ 签名验证成功！消息确实来自A" : 
                "✗ 签名验证失败！消息可能被篡改");
            outputArea.setText(step2Result.getText());
        });
        
        step2Panel.add(step2Btn, BorderLayout.NORTH);
        step2Panel.add(new JScrollPane(step2Result), BorderLayout.CENTER);
        
        // 步骤3: A用B的公钥加密
        JPanel step3Panel = new JPanel(new BorderLayout());
        JButton step3Btn = new JButton("步骤3: A用B的公钥加密");
        step3Btn.setBackground(new Color(255, 240, 200));
        JTextArea step3Result = new JTextArea(2, 40);
        step3Result.setEditable(false);
        step3Result.setBorder(BorderFactory.createTitledBorder("加密结果"));
        
        step3Btn.addActionListener(e -> {
            if (publicKeyB == null) {
                JOptionPane.showMessageDialog(this, "请先生成B的密钥对！");
                return;
            }
            
            String message = inputArea.getText();
            if (message.isEmpty()) {
                JOptionPane.showMessageDialog(this, "请输入消息！");
                return;
            }
            
            // A用B的公钥加密
            byte[] encrypted = RSAUtil.encrypt(message.getBytes(), publicKeyB);
            String encryptedBase64 = Base64.getEncoder().encodeToString(encrypted);
            
            step3Result.setText("加密（Base64）: " + 
                encryptedBase64.substring(0, Math.min(100, encryptedBase64.length())) + "...");
            outputArea.setText("加密结果:\n" + encryptedBase64);
        });
        
        step3Panel.add(step3Btn, BorderLayout.NORTH);
        step3Panel.add(new JScrollPane(step3Result), BorderLayout.CENTER);
        
        // 步骤4: B用自己的私钥解密
        JPanel step4Panel = new JPanel(new BorderLayout());
        JButton step4Btn = new JButton("步骤4: B用自己的私钥解密");
        step4Btn.setBackground(new Color(255, 200, 230));
        JTextArea step4Result = new JTextArea(2, 40);
        step4Result.setEditable(false);
        step4Result.setBorder(BorderFactory.createTitledBorder("解密结果"));
        
        step4Btn.addActionListener(e -> {
            if (privateKeyB == null) {
                JOptionPane.showMessageDialog(this, "请先生成B的密钥对！");
                return;
            }
            
            String encryptedText = outputArea.getText();
            if (!encryptedText.contains("加密结果")) {
                JOptionPane.showMessageDialog(this, "请先完成步骤3的加密！");
                return;
            }
            
            // 提取Base64加密数据
            String[] lines = encryptedText.split("\n");
            if (lines.length < 2) {
                JOptionPane.showMessageDialog(this, "加密数据格式错误！");
                return;
            }
            
            try {
                byte[] encrypted = Base64.getDecoder().decode(lines[1]);
                byte[] decrypted = RSAUtil.decrypt(encrypted, privateKeyB);
                
                step4Result.setText("解密结果: " + new String(decrypted));
                outputArea.setText("B解密后的消息:\n" + new String(decrypted));
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "解密失败: " + ex.getMessage());
            }
        });
        
        step4Panel.add(step4Btn, BorderLayout.NORTH);
        step4Panel.add(new JScrollPane(step4Result), BorderLayout.CENTER);
        
        // 一键完成所有步骤
        JPanel autoPanel = new JPanel(new BorderLayout());
        JButton autoBtn = new JButton("一键完成所有步骤");
        autoBtn.setBackground(new Color(220, 200, 255));
        autoBtn.setFont(new Font("宋体", Font.BOLD, 14));
        
        autoBtn.addActionListener(e -> {
            // 检查所有密钥
            if (privateKeyA == null || publicKeyA == null || 
                privateKeyB == null || publicKeyB == null) {
                JOptionPane.showMessageDialog(this, "请先生成A和B的完整密钥对！");
                return;
            }
            
            String message = inputArea.getText();
            if (message.isEmpty()) {
                JOptionPane.showMessageDialog(this, "请输入消息！");
                return;
            }
            
            // 执行所有步骤
            try {
                // 步骤1: A签名
                String hash = HashUtil.sha256(message);
                byte[] signature = SignUtil.sign(hash, privateKeyA);
                signatureArea.setText(bytesToHex(signature));
                
                // 步骤2: 验证签名
                boolean verified = SignUtil.verify(hash, signature, publicKeyA);
                
                // 步骤3: A用B的公钥加密
                byte[] encrypted = RSAUtil.encrypt(message.getBytes(), publicKeyB);
                String encryptedBase64 = Base64.getEncoder().encodeToString(encrypted);
                
                // 步骤4: B用自己的私钥解密
                byte[] decrypted = RSAUtil.decrypt(encrypted, privateKeyB);
                
                // 显示结果
                outputArea.setText(
                    "✓ 步骤1: A签名完成\n" +
                    (verified ? "✓ 步骤2: 签名验证成功\n" : "✗ 步骤2: 签名验证失败\n") +
                    "✓ 步骤3: 消息已加密\n" +
                    "✓ 步骤4: B解密结果: " + new String(decrypted)
                );
                
                JOptionPane.showMessageDialog(this, "所有步骤执行完成！");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "执行失败: " + ex.getMessage());
            }
        });
        
        autoPanel.add(autoBtn, BorderLayout.CENTER);
        
        // 添加到步骤面板
        stepsPanel.add(step1Panel);
        stepsPanel.add(step2Panel);
        stepsPanel.add(step3Panel);
        stepsPanel.add(step4Panel);
        stepsPanel.add(new JSeparator());
        stepsPanel.add(autoPanel);
        
        panel.add(stepsPanel);
        
        return panel;
    }
    
    /**
     * 创建密钥管理面板
     */
    private JPanel createKeyPanel() {
        JPanel panel = new JPanel(new GridLayout(2, 1, 10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // A的密钥区域
        JPanel keyAPanel = new JPanel(new BorderLayout());
        keyAPanel.setBorder(BorderFactory.createTitledBorder("A的密钥对"));
        
        JPanel keyAControls = new JPanel(new FlowLayout());
        JButton genKeyABtn = new JButton("生成新密钥");
        JButton saveKeyABtn = new JButton("保存密钥");
        JButton loadKeyABtn = new JButton("加载密钥");
        
        keyAControls.add(genKeyABtn);
        keyAControls.add(saveKeyABtn);
        keyAControls.add(loadKeyABtn);
        
        JPanel keyADisplay = new JPanel(new GridLayout(2, 1, 5, 5));
        pubKeyAText = new JTextArea(3, 50);
        pubKeyAText.setEditable(false);
        pubKeyAText.setBorder(BorderFactory.createTitledBorder("A的公钥"));
        
        privKeyAText = new JTextArea(3, 50);
        privKeyAText.setEditable(false);
        privKeyAText.setBorder(BorderFactory.createTitledBorder("A的私钥（保密！）"));
        
        keyADisplay.add(new JScrollPane(pubKeyAText));
        keyADisplay.add(new JScrollPane(privKeyAText));
        
        keyAPanel.add(keyAControls, BorderLayout.NORTH);
        keyAPanel.add(keyADisplay, BorderLayout.CENTER);
        
        // B的密钥区域
        JPanel keyBPanel = new JPanel(new BorderLayout());
        keyBPanel.setBorder(BorderFactory.createTitledBorder("B的密钥对"));
        
        JPanel keyBControls = new JPanel(new FlowLayout());
        JButton genKeyBBtn = new JButton("生成新密钥");
        JButton saveKeyBBtn = new JButton("保存密钥");
        JButton loadKeyBBtn = new JButton("加载密钥");
        
        keyBControls.add(genKeyBBtn);
        keyBControls.add(saveKeyBBtn);
        keyBControls.add(loadKeyBBtn);
        
        JPanel keyBDisplay = new JPanel(new GridLayout(2, 1, 5, 5));
        pubKeyBText = new JTextArea(3, 50);
        pubKeyBText.setEditable(false);
        pubKeyBText.setBorder(BorderFactory.createTitledBorder("B的公钥"));
        
        privKeyBText = new JTextArea(3, 50);
        privKeyBText.setEditable(false);
        privKeyBText.setBorder(BorderFactory.createTitledBorder("B的私钥（保密！）"));
        
        keyBDisplay.add(new JScrollPane(pubKeyBText));
        keyBDisplay.add(new JScrollPane(privKeyBText));
        
        keyBPanel.add(keyBControls, BorderLayout.NORTH);
        keyBPanel.add(keyBDisplay, BorderLayout.CENTER);
        
        // 添加事件监听器
        setupKeyEventListeners(genKeyABtn, saveKeyABtn, loadKeyABtn, 
                              genKeyBBtn, saveKeyBBtn, loadKeyBBtn);
        
        panel.add(keyAPanel);
        panel.add(keyBPanel);
        
        return panel;
    }
    
    /**
     * 设置基础功能事件监听器
     */
    private void setupBasicEventListeners(JButton genKeyBtn, JButton genKeyABtn, JButton genKeyBBtn,
                                         JButton hashBtn, JButton fileHashBtn, JButton encBtn,
                                         JButton decBtn, JButton fileEncBtn, JButton fileDecBtn,
                                         JButton signBtn, JButton verifyBtn, JButton fileSignBtn,
                                         JButton fileVerifyBtn) {
        
        // 生成对称密钥
        genKeyBtn.addActionListener(e -> {
            String type = (String) symBox.getSelectedItem();
            String key = null;
            if ("AES".equals(type)) {
                key = SymmetricCrypto.generateAESKey();
            } else {
                key = SymmetricCrypto.generateDESKey();
            }
            keyField.setText(key);
        });
        
        // 生成A的密钥对
        genKeyABtn.addActionListener(e -> {
            KeyPair kp = RSAUtil.generateKeyPair(2048);
            privateKeyA = kp.getPrivate();
            publicKeyA = kp.getPublic();
            
            // 更新显示
            pubKeyAText.setText("公钥（Base64）:\n" + 
                Base64.getEncoder().encodeToString(publicKeyA.getEncoded()));
            privKeyAText.setText("私钥（Base64）:\n" + 
                Base64.getEncoder().encodeToString(privateKeyA.getEncoded()));
            
            JOptionPane.showMessageDialog(this, "A的密钥对生成成功！");
        });
        
        // 生成B的密钥对
        genKeyBBtn.addActionListener(e -> {
            KeyPair kp = RSAUtil.generateKeyPair(2048);
            privateKeyB = kp.getPrivate();
            publicKeyB = kp.getPublic();
            
            // 更新显示
            pubKeyBText.setText("公钥（Base64）:\n" + 
                Base64.getEncoder().encodeToString(publicKeyB.getEncoded()));
            privKeyBText.setText("私钥（Base64）:\n" + 
                Base64.getEncoder().encodeToString(privateKeyB.getEncoded()));
            
            JOptionPane.showMessageDialog(this, "B的密钥对生成成功！");
        });
        
        // Hash计算
        hashBtn.addActionListener(e -> {
            String text = inputArea.getText();
            if (text.isEmpty()) {
                JOptionPane.showMessageDialog(this, "请输入文本！");
                return;
            }
            
            String algo = (String) hashBox.getSelectedItem();
            String hash;
            if ("MD5".equals(algo)) {
                hash = HashUtil.md5(text);
            } else {
                hash = HashUtil.sha256(text);
            }
            outputArea.setText(hash);
        });
        
        // 文件Hash
//        fileHashBtn.addActionListener(e -> {
//            JFileChooser chooser = new JFileChooser();
//            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
//                File file = chooser.getSelectedFile();
//                byte[] data = FileUtil.readFile(file);
//                
//                String algo = (String) hashBox.getSelectedItem();
//                String hash;
//                if ("MD5".equals(algo)) {
//                    hash = HashUtil.md5(data);
//                } else {
//                    hash = HashUtil.sha256(data);
//                }
//                outputArea.setText("文件Hash (" + algo + "):\n" + hash);
//            }
//        });
        
        // 对称加密
        encBtn.addActionListener(e -> {
            try {
                String text = inputArea.getText();
                String key = keyField.getText();
                if (text.isEmpty() || key.isEmpty()) {
                    JOptionPane.showMessageDialog(this, "请先输入文本和生成密钥！");
                    return;
                }
                
                byte[] data = text.getBytes("UTF-8");
                byte[] cipher = null;
                
                String algo = (String) symBox.getSelectedItem();
                if ("AES".equals(algo)) {
                    cipher = SymmetricCrypto.encryptAES(data, key);
                } else {
                    cipher = SymmetricCrypto.encryptDES(data, key);
                }
                
                outputArea.setText(bytesToHex(cipher));
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "加密失败: " + ex.getMessage());
            }
        });
        
        // 对称解密
        decBtn.addActionListener(e -> {
            try {
                String hex = inputArea.getText();
                String key = keyField.getText();
                
                if (hex.isEmpty() || key.isEmpty()) {
                    JOptionPane.showMessageDialog(this, "请先输入密文和密钥！");
                    return;
                }
                
                byte[] data = hexToBytes(hex);
                byte[] plain = null;
                
                String algo = (String) symBox.getSelectedItem();
                if ("AES".equals(algo)) {
                    plain = SymmetricCrypto.decryptAES(data, key);
                } else {
                    plain = SymmetricCrypto.decryptDES(data, key);
                }
                
                outputArea.setText(new String(plain, "UTF-8"));
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "解密失败: " + ex.getMessage());
            }
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
                
                try {
                    byte[] cipher;
                    if ("AES".equals(symBox.getSelectedItem())) {
                        cipher = SymmetricCrypto.encryptAES(data, key);
                    } else {
                        cipher = SymmetricCrypto.encryptDES(data, key);
                    }
                    
                    File save = new File(file.getAbsolutePath() + ".enc");
                    FileUtil.saveFile(cipher, save);
                    JOptionPane.showMessageDialog(this, "文件已加密: " + save.getName());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "加密失败: " + ex.getMessage());
                }
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
                
                try {
                    byte[] plain;
                    if ("AES".equals(symBox.getSelectedItem())) {
                        plain = SymmetricCrypto.decryptAES(data, key);
                    } else {
                        plain = SymmetricCrypto.decryptDES(data, key);
                    }
                    
                    String originalName = file.getName();
                    if (originalName.endsWith(".enc")) {
                        originalName = originalName.substring(0, originalName.length() - 4);
                    }
                    File save = new File(file.getParent(), "decrypted_" + originalName);
                    FileUtil.saveFile(plain, save);
                    JOptionPane.showMessageDialog(this, "文件已解密: " + save.getName());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "解密失败: " + ex.getMessage());
                }
            }
        });
        
        // 签名
        signBtn.addActionListener(e -> {
            if (privateKeyA == null) {
                JOptionPane.showMessageDialog(this, "请先生成A的密钥对！");
                return;
            }
            
            String text = inputArea.getText();
            if (text.isEmpty()) {
                JOptionPane.showMessageDialog(this, "请输入文本！");
                return;
            }
            
            String algo = (String) hashBox.getSelectedItem();
            String hash;
            if ("MD5".equals(algo)) {
                hash = HashUtil.md5(text);
            } else {
                hash = HashUtil.sha256(text);
            }
            
            try {
                byte[] sign = SignUtil.sign(hash, privateKeyA);
                signatureArea.setText(bytesToHex(sign));
                outputArea.setText("签名完成（" + algo + "）");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "签名失败: " + ex.getMessage());
            }
        });
        
        // 验证签名
        verifyBtn.addActionListener(e -> {
            if (publicKeyA == null) {
                JOptionPane.showMessageDialog(this, "请先生成A的密钥对！");
                return;
            }
            
            String text = inputArea.getText();
            String signHex = signatureArea.getText();
            if (text.isEmpty() || signHex.isEmpty()) {
                JOptionPane.showMessageDialog(this, "请先输入文本和签名！");
                return;
            }
            
            String algo = (String) hashBox.getSelectedItem();
            String hash;
            if ("MD5".equals(algo)) {
                hash = HashUtil.md5(text);
            } else {
                hash = HashUtil.sha256(text);
            }
            
            try {
                boolean ok = SignUtil.verify(hash, hexToBytes(signHex), publicKeyA);
                outputArea.setText(ok ? "✓ 签名验证成功" : "✗ 签名验证失败");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "验证失败: " + ex.getMessage());
            }
        });
    }
    
    /**
     * 设置密钥管理事件监听器
     */
    private void setupKeyEventListeners(JButton genKeyABtn, JButton saveKeyABtn, JButton loadKeyABtn,
                                       JButton genKeyBBtn, JButton saveKeyBBtn, JButton loadKeyBBtn) {
        
        // 生成A的密钥
        genKeyABtn.addActionListener(e -> {
            KeyPair kp = RSAUtil.generateKeyPair(2048);
            privateKeyA = kp.getPrivate();
            publicKeyA = kp.getPublic();
            
            pubKeyAText.setText("公钥（Base64）:\n" + 
                Base64.getEncoder().encodeToString(publicKeyA.getEncoded()));
            privKeyAText.setText("私钥（Base64）:\n" + 
                Base64.getEncoder().encodeToString(privateKeyA.getEncoded()));
            
            JOptionPane.showMessageDialog(this, "A的密钥对生成成功！");
        });
        
        // 保存A的密钥
        saveKeyABtn.addActionListener(e -> {
            if (privateKeyA == null || publicKeyA == null) {
                JOptionPane.showMessageDialog(this, "请先生成A的密钥对！");
                return;
            }
            
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("保存A的私钥");
            if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                File file = chooser.getSelectedFile();
                byte[] keyData = privateKeyA.getEncoded();
                FileUtil.saveFile(keyData, file);
                JOptionPane.showMessageDialog(this, "私钥已保存到: " + file.getName());
            }
        });
        
        // 生成B的密钥
        genKeyBBtn.addActionListener(e -> {
            KeyPair kp = RSAUtil.generateKeyPair(2048);
            privateKeyB = kp.getPrivate();
            publicKeyB = kp.getPublic();
            
            pubKeyBText.setText("公钥（Base64）:\n" + 
                Base64.getEncoder().encodeToString(publicKeyB.getEncoded()));
            privKeyBText.setText("私钥（Base64）:\n" + 
                Base64.getEncoder().encodeToString(privateKeyB.getEncoded()));
            
            JOptionPane.showMessageDialog(this, "B的密钥对生成成功！");
        });
    }
    
    /**
     * 工具函数：字节数组转十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    /**
     * 工具函数：十六进制字符串转字节数组
     */
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] result = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            result[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return result;
    }
    
    /**
     * 主方法
     */
    public static void main(String[] args) {
        // 设置界面风格
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        SwingUtilities.invokeLater(() -> {
            new MainFrame();
        });
    }
}