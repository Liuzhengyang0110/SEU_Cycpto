package ui;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Arrays;

import crypto.hash.HashUtil;
import crypto.symmetric.SymmetricCrypto;
import crypto.rsa.RSAUtil;
import crypto.sign.SignUtil;
import utils.FileUtil;
import utils.MessageUtil;
import utils.MessageUtil.MessageParts;
import java.awt.event.*;
import java.util.HashMap;
import java.util.Map;
import java.awt.datatransfer.*;
import javax.swing.event.DocumentListener;
import javax.swing.event.DocumentEvent;

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
	private JTextArea diagramArea;

	// 组合框
	private JComboBox<String> hashBox;
	private JComboBox<String> symBox;

	// 输入框
	private JTextField keyField;

	// 临时存储变量（用于流程演示）
	private byte[] currentSignature;
	private String currentCombinedMessage;
	private byte[] encryptedCombinedData; // 对称加密的密文
	private byte[] encryptedSymmetricKey; // RSA加密的对称密钥
	private String symmetricKey; // 对称密钥K

	// 添加成员变量存储步骤结果
	private Map<String, String> stepResults = new HashMap<>();
	
	private String currentMessage = ""; // 当前加密的消息
	private boolean[] stepCompleted = new boolean[6]; // 步骤完成状态

	public MainFrame() {
		setTitle("密码学课程大作业 - 混合加密系统");
		setSize(1200, 800);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setLocationRelativeTo(null);

		// 创建主面板
		JPanel mainPanel = new JPanel(new BorderLayout());

		// 顶部标题
		JLabel title = new JLabel("密码学课程大作业 - 混合加密系统", JLabel.CENTER);
		title.setFont(new Font("宋体", Font.BOLD, 22));
		title.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0));
		mainPanel.add(title, BorderLayout.NORTH);

		// 创建选项卡
		JTabbedPane tabbedPane = new JTabbedPane();

		// 选项卡1: 基础功能
		tabbedPane.addTab("基础功能", createBasicPanel());

		// 选项卡2: 完整混合加密流程
		tabbedPane.addTab("混合加密流程", createHybridFlowPanel());

		// 选项卡3: 密钥管理
		tabbedPane.addTab("密钥管理", createKeyPanel());

		mainPanel.add(tabbedPane, BorderLayout.CENTER);

		// 底部状态栏
		JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		statusPanel.setBorder(BorderFactory.createEtchedBorder());
		JLabel statusLabel = new JLabel("就绪 - 使用混合加密：对称加密M||S，RSA加密对称密钥");
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
		return createBasicPanelContent();
	}

	private JPanel createBasicPanelContent() {
		JPanel panel = new JPanel(new GridLayout(1, 2, 10, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		// 左侧：输入输出区域
		JPanel leftPanel = new JPanel(new BorderLayout(5, 5));

		// 输入区域
		JPanel inputPanel = new JPanel(new BorderLayout());
		inputArea = new JTextArea(8, 35);
		inputArea.setLineWrap(true);
		JScrollPane inputScroll = new JScrollPane(inputArea);
		inputScroll.setBorder(BorderFactory.createTitledBorder("输入明文/文本"));
		inputPanel.add(inputScroll, BorderLayout.CENTER);

		// 输出区域
		JPanel outputPanel = new JPanel(new BorderLayout());
		outputArea = new JTextArea(8, 35);
		outputArea.setLineWrap(true);
		outputArea.setEditable(false);
		JScrollPane outputScroll = new JScrollPane(outputArea);
		outputScroll.setBorder(BorderFactory.createTitledBorder("输出结果"));
		outputPanel.add(outputScroll, BorderLayout.CENTER);

		// 签名区域
		JPanel signaturePanel = new JPanel(new BorderLayout());
		signatureArea = new JTextArea(4, 35);
		signatureArea.setLineWrap(true);
		JScrollPane signatureScroll = new JScrollPane(signatureArea);
		signatureScroll.setBorder(BorderFactory.createTitledBorder("数字签名（Base64格式）"));
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
		hashBox = new JComboBox<>(new String[] { "SHA-256", "MD5" });
		algoPanel.add(hashBox);

		algoPanel.add(new JLabel("对称加密:"));
		symBox = new JComboBox<>(new String[] { "AES", "DES" });
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

		// 数字签名功能（基础版）
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
		setupBasicEventListeners(genKeyBtn, genKeyABtn, genKeyBBtn, hashBtn, fileHashBtn, encBtn, decBtn, fileEncBtn,
				fileDecBtn, signBtn, verifyBtn, fileSignBtn, fileVerifyBtn);

		panel.add(leftPanel);
		panel.add(rightPanel);

		return panel;
	}
	
	/**
	 * createHybridFlowPanel 方法中的步骤面板创建
	 */	
	private JPanel createHybridFlowPanel() {
	    JPanel panel = new JPanel();
	    panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
	    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
	    
	    // 流程图说明
	    JTextArea flowDesc = new JTextArea(
	        "══════════════════ 混合加密通信流程 ══════════════════\n\n" +
	        "完整流程（对称加密 + RSA加密）：\n\n" +
	        "发送方A的操作流程：\n" +
	        "1. 计算消息的Hash值：h = H(M)\n" +
	        "2. 用私钥RKa对Hash值签名：S = Sig(RKa, h)\n" +
	        "3. 组合明文和签名：M || S\n" +
	        "4. 生成对称密钥 K\n" +
	        "5. 用K加密组合数据：C1 = E(K, M || S)\n" +
	        "6. 用B的公钥UKb加密K：C2 = E(UKb, K)\n" +
	        "7. 发送：C2 || C1 给B\n\n" +
	        "接收方B的操作流程：\n" +
	        "1. 用私钥RKb解密出K：K = D(RKb, C2)\n" +
	        "2. 用K解密组合数据：M || S = D(K, C1)\n" +
	        "3. 分离出明文M和签名S\n" +
	        "4. 计算Hash值：h' = H(M)\n" +
	        "5. 用A的公钥UKa验证签名：Ver(UKa, h', S)\n\n" +
	        "注：|| 表示组合操作，K是对称密钥（AES/DES）"
	    );
	    flowDesc.setEditable(false);
	    flowDesc.setFont(new Font("等线", Font.PLAIN, 14));
	    flowDesc.setBackground(new Color(240, 245, 255));
	    flowDesc.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
	    
	    panel.add(new JScrollPane(flowDesc));
	    panel.add(Box.createVerticalStrut(15));
	    
	    // 当前消息显示区域
	    JPanel messagePanel = new JPanel(new BorderLayout());
	    messagePanel.setBorder(BorderFactory.createTitledBorder("当前加密的消息"));
	    JTextArea messageDisplay = new JTextArea(2, 50);
	    messageDisplay.setEditable(false);
	    messageDisplay.setText(currentMessage.isEmpty() ? "请在基础功能面板输入待加密的消息" : currentMessage);
	    messageDisplay.setFont(new Font("等线", Font.PLAIN, 12));
	    messageDisplay.setBackground(new Color(255, 255, 240));
	    messagePanel.add(new JScrollPane(messageDisplay), BorderLayout.CENTER);
	    
	    JButton refreshMsgBtn = new JButton("刷新消息");
	    refreshMsgBtn.addActionListener(e -> {
	        currentMessage = inputArea.getText();
	        messageDisplay.setText(currentMessage.isEmpty() ? "请在左侧输入消息" : currentMessage);
	        // 重置所有步骤状态
	        resetStepStatus();
	        JOptionPane.showMessageDialog(this, "消息已更新，所有步骤状态已重置");
	    });
	    messagePanel.add(refreshMsgBtn, BorderLayout.EAST);
	    
	    panel.add(messagePanel);
	    panel.add(Box.createVerticalStrut(15));
	    
	    // 初始化步骤完成状态
	    resetStepStatus();
	    
	    // 流程步骤面板
	    JPanel stepsPanel = new JPanel(new GridLayout(7, 1, 10, 15));
	    stepsPanel.setBorder(BorderFactory.createTitledBorder("分步执行（必须按顺序执行）"));
	    
	    // 步骤1: A计算Hash并签名
	    JPanel step1Panel = createStepPanel(
	        "步骤1: A计算Hash并用私钥签名",
	        new Color(200, 230, 255),
	        e -> performStep1(),
	        "step1",
	        true  // 第一步始终可执行
	    );
	    
	    // 步骤2: A组合 M || S（默认禁用）
	    JPanel step2Panel = createStepPanel(
	        "步骤2: A组合明文和签名（M || S）",
	        new Color(180, 220, 255),
	        e -> performStep2(),
	        "step2",
	        false  // 需要步骤1完成后才能执行
	    );
	    
	    // 步骤3: 生成对称密钥K（默认禁用）
	    JPanel step3Panel = createStepPanel(
	        "步骤3: 生成对称密钥 K",
	        new Color(160, 210, 255),
	        e -> performStep3(),
	        "step3",
	        false  // 需要步骤2完成后才能执行
	    );
	    
	    // 步骤4: 用K加密 M || S（默认禁用）
	    JPanel step4Panel = createStepPanel(
	        "步骤4: 用对称密钥K加密组合数据",
	        new Color(140, 200, 255),
	        e -> performStep4(),
	        "step4",
	        false  // 需要步骤3完成后才能执行
	    );
	    
	    // 步骤5: 用B的公钥加密K（默认禁用）
	    JPanel step5Panel = createStepPanel(
	        "步骤5: 用B的公钥加密对称密钥K",
	        new Color(120, 190, 255),
	        e -> performStep5(),
	        "step5",
	        false  // 需要步骤4完成后才能执行
	    );
	    
	    // 步骤6: B解密并验证（默认禁用）
	    JPanel step6Panel = createStepPanel(
	        "步骤6: B解密密钥和数据，验证签名",
	        new Color(100, 180, 255),
	        e -> performStep6(),
	        "step6",
	        false  // 需要步骤5完成后才能执行
	    );
	    
	    // 存储面板引用以便后续启用/禁用
	    Map<String, JPanel> stepPanels = new HashMap<>();
	    stepPanels.put("step1", step1Panel);
	    stepPanels.put("step2", step2Panel);
	    stepPanels.put("step3", step3Panel);
	    stepPanels.put("step4", step4Panel);
	    stepPanels.put("step5", step5Panel);
	    stepPanels.put("step6", step6Panel);
	    
	    // 一键完成按钮
	    JPanel autoPanel = new JPanel(new BorderLayout());
	    JButton autoBtn = new JButton("⚡ 一键完成所有步骤");
	    autoBtn.setBackground(new Color(255, 220, 100));
	    autoBtn.setFont(new Font("宋体", Font.BOLD, 16));
	    autoBtn.setForeground(Color.BLACK);
	    
	    autoBtn.addActionListener(e -> {
	        try {
	            // 重置状态
	            resetStepStatus();
	            updateStepButtons(stepPanels);
	            
	            // 检查消息
	            currentMessage = inputArea.getText();
	            if (currentMessage.isEmpty()) {
	                JOptionPane.showMessageDialog(this, "❌ 请先输入要加密的消息！");
	                return;
	            }
	            
	            // 更新消息显示
	            messageDisplay.setText(currentMessage);
	            
	            // 执行所有步骤
	            if (!performStep1()) {
	                JOptionPane.showMessageDialog(this, "❌ 步骤1失败，流程终止");
	                return;
	            }
	            updateStepResultDisplay("step1", step1Panel);
	            stepCompleted[0] = true;
	            updateStepButtons(stepPanels);
	            
	            Thread.sleep(300);
	            
	            if (!performStep2()) {
	                JOptionPane.showMessageDialog(this, "❌ 步骤2失败，流程终止");
	                return;
	            }
	            updateStepResultDisplay("step2", step2Panel);
	            stepCompleted[1] = true;
	            updateStepButtons(stepPanels);
	            
	            Thread.sleep(300);
	            
	            if (!performStep3()) {
	                JOptionPane.showMessageDialog(this, "❌ 步骤3失败，流程终止");
	                return;
	            }
	            updateStepResultDisplay("step3", step3Panel);
	            stepCompleted[2] = true;
	            updateStepButtons(stepPanels);
	            
	            Thread.sleep(300);
	            
	            if (!performStep4()) {
	                JOptionPane.showMessageDialog(this, "❌ 步骤4失败，流程终止");
	                return;
	            }
	            updateStepResultDisplay("step4", step4Panel);
	            stepCompleted[3] = true;
	            updateStepButtons(stepPanels);
	            
	            Thread.sleep(300);
	            
	            if (!performStep5()) {
	                JOptionPane.showMessageDialog(this, "❌ 步骤5失败，流程终止");
	                return;
	            }
	            updateStepResultDisplay("step5", step5Panel);
	            stepCompleted[4] = true;
	            updateStepButtons(stepPanels);
	            
	            Thread.sleep(300);
	            
	            if (!performStep6()) {
	                JOptionPane.showMessageDialog(this, "❌ 步骤6失败，流程终止");
	                return;
	            }
	            updateStepResultDisplay("step6", step6Panel);
	            stepCompleted[5] = true;
	            updateStepButtons(stepPanels);
	            
	            JOptionPane.showMessageDialog(this, "✅ 所有步骤执行完成！");
	        } catch (Exception ex) {
	            JOptionPane.showMessageDialog(this, "❌ 执行失败: " + ex.getMessage());
	        }
	    });
	    
	    autoPanel.add(autoBtn, BorderLayout.CENTER);
	    
	    // 重置按钮
	    JButton resetBtn = new JButton("🔄 重置所有步骤");
	    resetBtn.setBackground(new Color(255, 200, 200));
	    resetBtn.addActionListener(e -> {
	        resetStepStatus();
	        updateStepButtons(stepPanels);
	        stepResults.clear();
	        // 清空所有步骤结果显示
	        for (JPanel stepPanel : stepPanels.values()) {
	            updateStepResultDisplay("", stepPanel);
	        }
	        JOptionPane.showMessageDialog(this, "所有步骤已重置");
	    });
	    autoPanel.add(resetBtn, BorderLayout.EAST);
	    
	    // 添加到步骤面板
	    stepsPanel.add(step1Panel);
	    stepsPanel.add(step2Panel);
	    stepsPanel.add(step3Panel);
	    stepsPanel.add(step4Panel);
	    stepsPanel.add(step5Panel);
	    stepsPanel.add(step6Panel);
	    
	    panel.add(stepsPanel);
	    panel.add(Box.createVerticalStrut(15));
	    panel.add(autoPanel);
	    
	    return panel;
	}
	
	/**
	 * 更新步骤结果显示
	 */
	private void updateStepResultDisplay(String stepId, JPanel stepPanel) {
	    SwingUtilities.invokeLater(() -> {
	        String result = stepResults.get(stepId);
	        if (result != null && !result.isEmpty()) {
	            // 查找面板中的结果区域
	            for (Component comp : stepPanel.getComponents()) {
	                if (comp instanceof JScrollPane) {
	                    JScrollPane scrollPane = (JScrollPane) comp;
	                    Component view = scrollPane.getViewport().getView();
	                    if (view instanceof JTextArea) {
	                        ((JTextArea) view).setText(result);
	                        break;
	                    }
	                }
	            }
	        }
	    });
	}

	/**
	 * 创建步骤面板（修改版，支持启用/禁用）
	 */
	private JPanel createStepPanel(String title, Color color, ActionListener action, String stepId, boolean enabled) {
	    JPanel panel = new JPanel(new BorderLayout(5, 5));
	    panel.setBorder(BorderFactory.createCompoundBorder(
	        BorderFactory.createLineBorder(color, 2),
	        BorderFactory.createEmptyBorder(5, 5, 5, 5)
	    ));
	    
	    JButton button = new JButton(title);
	    button.setBackground(color);
	    button.setFont(new Font("宋体", Font.BOLD, 14));
	    
	    if (!enabled) {
	        button.setEnabled(false);
	        button.setBackground(color.darker());
	        button.setForeground(Color.GRAY);
	    }
	    
	    // 为按钮添加自定义属性
	    button.putClientProperty("stepId", stepId);
	    
	    // 修改ActionListener，将结果存储并显示
	    button.addActionListener(e -> {
	        // 执行步骤
	        boolean success = executeStep(stepId, action);
	        
	        if (success) {
	            // 标记步骤完成
	            int stepIndex = Integer.parseInt(stepId.replace("step", "")) - 1;
	            stepCompleted[stepIndex] = true;
	            
	            // 延迟一下，确保步骤执行完成
	            SwingUtilities.invokeLater(() -> {
	                // 获取结果文本
	                String result = getStepResult(stepId);
	                if (result != null && !result.isEmpty()) {
	                    // 显示在当前面板的结果区域
	                    JTextArea resultArea = findResultAreaInPanel(panel);
	                    if (resultArea != null) {
	                        resultArea.setText(result);
	                    }
	                    
	                    // 同时在主输出区域也显示
	                    outputArea.append("\n\n" + title + " 结果:\n" + result);
	                    outputArea.setCaretPosition(outputArea.getDocument().getLength());
	                }
	                
	                // 更新所有按钮状态
	                updateStepButtons(getAllStepPanels());
	            });
	        }
	    });
	    
	    // 结果区域
	    JTextArea resultArea = new JTextArea(3, 50);
	    resultArea.setEditable(false);
	    resultArea.setFont(new Font("等线", Font.PLAIN, 11));
	    resultArea.setBorder(BorderFactory.createTitledBorder("执行结果"));
	    resultArea.setLineWrap(true);
	    resultArea.setWrapStyleWord(true);
	    
	    // 存储结果区域引用
	    panel.putClientProperty("resultArea", resultArea);
	    panel.putClientProperty("button", button);
	    
	    panel.add(button, BorderLayout.NORTH);
	    panel.add(new JScrollPane(resultArea), BorderLayout.CENTER);
	    
	    return panel;
	}
	
	/**
	 * 执行步骤并返回是否成功
	 */
	private boolean executeStep(String stepId, ActionListener action) {
	    try {
	        // 检查当前消息
	        currentMessage = inputArea.getText();
	        if (currentMessage.isEmpty() && !stepId.equals("step1")) {
	            JOptionPane.showMessageDialog(this, "❌ 请先输入消息并完成步骤1！");
	            return false;
	        }
	        
	        // 执行步骤
	        action.actionPerformed(new ActionEvent(this, ActionEvent.ACTION_PERFORMED, stepId));
	        return true;
	    } catch (Exception ex) {
	        // 将错误信息存储到结果中
	        stepResults.put(stepId, "❌ 执行失败: " + ex.getMessage());
	        JOptionPane.showMessageDialog(this, "❌ " + stepId + " 执行失败: " + ex.getMessage());
	        return false;
	    }
	}

	/**
	 * 获取所有步骤面板（简化版，实际需要从UI获取）
	 */
	private Map<String, JPanel> getAllStepPanels() {
	    // 在实际应用中，这里应该从UI组件树中获取
	    // 这里返回一个空Map，实际使用时需要实现
	    return new HashMap<>();
	}

	/**
	 * 更新步骤按钮状态
	 */
	private void updateStepButtons(Map<String, JPanel> stepPanels) {
	    SwingUtilities.invokeLater(() -> {
	        // 启用步骤1（始终可用）
	        enableStepButton(stepPanels.get("step1"), true);
	        
	        // 步骤2：需要步骤1完成
	        boolean step2Enabled = stepCompleted[0];
	        enableStepButton(stepPanels.get("step2"), step2Enabled);
	        
	        // 步骤3：需要步骤2完成
	        boolean step3Enabled = stepCompleted[1];
	        enableStepButton(stepPanels.get("step3"), step3Enabled);
	        
	        // 步骤4：需要步骤3完成
	        boolean step4Enabled = stepCompleted[2];
	        enableStepButton(stepPanels.get("step4"), step4Enabled);
	        
	        // 步骤5：需要步骤4完成
	        boolean step5Enabled = stepCompleted[3];
	        enableStepButton(stepPanels.get("step5"), step5Enabled);
	        
	        // 步骤6：需要步骤5完成
	        boolean step6Enabled = stepCompleted[4];
	        enableStepButton(stepPanels.get("step6"), step6Enabled);
	    });
	}

	/**
	 * 启用/禁用步骤按钮
	 */
	private void enableStepButton(JPanel stepPanel, boolean enabled) {
	    if (stepPanel == null) return;
	    
	    JButton button = (JButton) stepPanel.getClientProperty("button");
	    if (button != null) {
	        button.setEnabled(enabled);
	        Color originalColor = button.getBackground();
	        if (enabled) {
	            button.setBackground(originalColor.brighter());
	            button.setForeground(Color.BLACK);
	        } else {
	            button.setBackground(originalColor.darker());
	            button.setForeground(Color.GRAY);
	        }
	    }
	}

	/**
	 * 重置步骤状态
	 */
	private void resetStepStatus() {
	    stepCompleted = new boolean[6];
	    stepResults.clear();
	    currentMessage = inputArea.getText();
	}
	
	/**
	 * 在面板中查找结果区域
	 */
	private JTextArea findResultAreaInPanel(JPanel panel) {
		for (Component comp : panel.getComponents()) {
			if (comp instanceof JScrollPane) {
				JScrollPane scrollPane = (JScrollPane) comp;
				Component view = scrollPane.getViewport().getView();
				if (view instanceof JTextArea) {
					return (JTextArea) view;
				}
			}
		}
		return null;
	}

	/**
	 * 获取步骤执行结果
	 */
	private String getStepResult(String stepId) {
		// 这里根据步骤ID返回相应的结果
		// 可以修改每个步骤函数，将结果存储到成员变量中
		return stepResults.getOrDefault(stepId, "");
	}

	/**
	 * 步骤1: A计算Hash并用私钥签名（修改版，返回是否成功）
	 */
	private boolean performStep1() {
	    currentMessage = inputArea.getText();
	    if (currentMessage.isEmpty()) {
	        String error = "❌ 失败：请先输入要加密的消息！";
	        stepResults.put("step1", error);
	        JOptionPane.showMessageDialog(this, error);
	        return false;
	    }
	    
	    if (privateKeyA == null) {
	        String error = "❌ 失败：未生成A的密钥对！";
	        stepResults.put("step1", error);
	        JOptionPane.showMessageDialog(this, error);
	        return false;
	    }
	    
	    try {
	        // 计算Hash
	        String algo = (String) hashBox.getSelectedItem();
	        String hash;
	        if ("MD5".equals(algo)) {
	            hash = HashUtil.md5(currentMessage);
	        } else {
	            hash = HashUtil.sha256(currentMessage);
	        }
	        
	        // 用A的私钥签名
	        currentSignature = SignUtil.sign(hash, privateKeyA);
	        
	        // 显示结果
	        String sigBase64 = Base64.getEncoder().encodeToString(currentSignature);
	        signatureArea.setText(sigBase64);
	        
	        // 生成步骤结果文本
	        String result = 
	            "✅ 步骤完成\n" +
	            "加密的消息: " + (currentMessage.length() > 50 ? currentMessage.substring(0, 50) + "..." : currentMessage) + "\n" +
	            "消息长度: " + currentMessage.length() + " 字符\n" +
	            "Hash算法: " + algo + "\n" +
	            "Hash值: " + hash.substring(0, Math.min(20, hash.length())) + "...\n" +
	            "签名长度: " + currentSignature.length + " 字节\n" +
	            "签名摘要: " + sigBase64.substring(0, Math.min(30, sigBase64.length())) + "...";
	        
	        stepResults.put("step1", result);
	        
	        // 在主输出区域也显示
	        outputArea.setText(
	            "步骤1完成：A对消息完成签名\n" +
	            "================================\n" +
	            "消息: " + currentMessage + "\n" +
	            "================================\n" +
	            result
	        );
	        
	        return true;
	        
	    } catch (Exception ex) {
	        String error = "❌ 签名失败: " + ex.getMessage();
	        stepResults.put("step1", error);
	        JOptionPane.showMessageDialog(this, error);
	        return false;
	    }
	}

	/**
	 * 步骤2: A组合明文和签名（M || S）（修改版，返回是否成功）
	 */
	private boolean performStep2() {
	    if (currentSignature == null) {
	        String error = "❌ 失败：请先完成步骤1生成签名！";
	        stepResults.put("step2", error);
	        JOptionPane.showMessageDialog(this, error);
	        return false;
	    }
	    
	    try {
	        // 使用正确的组合方式
	        currentCombinedMessage = MessageUtil.combineMessageAndSignature(currentMessage, currentSignature);
	        
	        // 生成步骤结果文本
	        String result = 
	            "✅ 步骤完成\n" +
	            "消息长度: " + currentMessage.length() + " 字符\n" +
	            "签名长度: " + currentSignature.length + " 字节\n" +
	            "组合格式: [长度]|消息|SIG|签名\n" +
	            "组合后长度: " + currentCombinedMessage.length() + " 字符\n" +
	            "组合数据示例: " + currentCombinedMessage.substring(0, Math.min(80, currentCombinedMessage.length())) + "...";
	        
	        stepResults.put("step2", result);
	        
	        // 在主输出区域也显示
	        outputArea.setText(
	            "步骤2完成：明文与签名组合（M || S）\n" +
	            "================================\n" +
	            "原始消息: " + currentMessage + "\n" +
	            "================================\n" +
	            result
	        );
	        
	        return true;
	        
	    } catch (Exception ex) {
	        String error = "❌ 组合失败: " + ex.getMessage();
	        stepResults.put("step2", error);
	        JOptionPane.showMessageDialog(this, error);
	        return false;
	    }
	}

	/**
	 * 步骤3: 生成对称密钥K（修改版，返回是否成功）
	 */
	private boolean performStep3() {
	    try {
	        // 根据选择的对称算法生成密钥
	        String algo = (String) symBox.getSelectedItem();
	        if ("AES".equals(algo)) {
	            symmetricKey = SymmetricCrypto.generateAESKey();
	        } else {
	            symmetricKey = SymmetricCrypto.generateDESKey();
	        }
	        
	        // 生成步骤结果文本
	        String result = 
	            "✅ 步骤完成\n" +
	            "对称算法: " + algo + "\n" +
	            "密钥: " + symmetricKey + "\n" +
	            "密钥长度: " + symmetricKey.length() + " 字符\n" +
	            "密钥类型: " + (algo.equals("AES") ? "AES-256位" : "DES-56位");
	        
	        stepResults.put("step3", result);
	        
	        // 更新密钥输入框
	        keyField.setText(symmetricKey);
	        
	        // 在主输出区域也显示
	        outputArea.setText(
	            "步骤3完成：生成对称密钥 K\n" +
	            "================================\n" +
	            "消息: " + currentMessage + "\n" +
	            "================================\n" +
	            result
	        );
	        
	        return true;
	        
	    } catch (Exception ex) {
	        String error = "❌ 生成密钥失败: " + ex.getMessage();
	        stepResults.put("step3", error);
	        JOptionPane.showMessageDialog(this, error);
	        return false;
	    }
	}

	/**
	 * 步骤4: 用对称密钥K加密组合数据（修改版，返回是否成功）
	 */
	private boolean performStep4() {
	    if (currentCombinedMessage == null || symmetricKey == null) {
	        String error = "❌ 失败：请先完成步骤2和3！";
	        stepResults.put("step4", error);
	        JOptionPane.showMessageDialog(this, error);
	        return false;
	    }
	    
	    try {
	        // 获取对称算法
	        String algo = (String) symBox.getSelectedItem();
	        
	        // 用对称密钥K加密组合数据
	        byte[] combinedBytes = currentCombinedMessage.getBytes("UTF-8");
	        
	        if ("AES".equals(algo)) {
	            encryptedCombinedData = SymmetricCrypto.encryptAES(combinedBytes, symmetricKey);
	        } else {
	            encryptedCombinedData = SymmetricCrypto.encryptDES(combinedBytes, symmetricKey);
	        }
	        
	        // 生成步骤结果文本
	        String result = 
	            "✅ 步骤完成\n" +
	            "加密的消息: " + (currentMessage.length() > 50 ? currentMessage.substring(0, 50) + "..." : currentMessage) + "\n" +
	            "对称算法: " + algo + "\n" +
	            "原始数据长度: " + combinedBytes.length + " 字节\n" +
	            "加密后长度: " + encryptedCombinedData.length + " 字节\n" +
	            "加密率: " + String.format("%.2f", (double)encryptedCombinedData.length/combinedBytes.length) + "\n" +
	            "密文摘要: " + 
	            Base64.getEncoder().encodeToString(encryptedCombinedData).substring(0, Math.min(40, Base64.getEncoder().encodeToString(encryptedCombinedData).length())) + "...";
	        
	        stepResults.put("step4", result);
	        
	        // 在主输出区域也显示
	        outputArea.setText(
	            "步骤4完成：用对称密钥K加密 M || S\n" +
	            "================================\n" +
	            "消息: " + currentMessage + "\n" +
	            "================================\n" +
	            result
	        );
	        
	        return true;
	        
	    } catch (Exception ex) {
	        String error = "❌ 对称加密失败: " + ex.getMessage();
	        stepResults.put("step4", error);
	        JOptionPane.showMessageDialog(this, error);
	        return false;
	    }
	}

	/**
	 * 步骤5: 用B的公钥加密对称密钥K（修改版，返回是否成功）
	 */
	private boolean performStep5() {
	    if (publicKeyB == null) {
	        String error = "❌ 失败：请先生成B的密钥对！";
	        stepResults.put("step5", error);
	        JOptionPane.showMessageDialog(this, error);
	        return false;
	    }
	    
	    if (symmetricKey == null) {
	        String error = "❌ 失败：请先完成步骤3生成对称密钥！";
	        stepResults.put("step5", error);
	        JOptionPane.showMessageDialog(this, error);
	        return false;
	    }
	    
	    try {
	        // 用B的公钥加密对称密钥K
	        encryptedSymmetricKey = RSAUtil.encrypt(
	            symmetricKey.getBytes("UTF-8"), 
	            publicKeyB
	        );
	        
	        String encryptedKeyBase64 = Base64.getEncoder().encodeToString(encryptedSymmetricKey);
	        
	        // 生成步骤结果文本
	        String result = 
	            "✅ 步骤完成\n" +
	            "加密的消息: " + (currentMessage.length() > 50 ? currentMessage.substring(0, 50) + "..." : currentMessage) + "\n" +
	            "RSA算法: 2048位\n" +
	            "对称密钥K: " + symmetricKey + "\n" +
	            "RSA加密后长度: " + encryptedSymmetricKey.length + " 字节\n" +
	            "加密密钥摘要: " + encryptedKeyBase64.substring(0, Math.min(40, encryptedKeyBase64.length())) + "...\n" +
	            "准备发送数据包:\n" +
	            "  - RSA加密的K: " + encryptedSymmetricKey.length + " 字节\n" +
	            "  - 对称加密的M||S: " + encryptedCombinedData.length + " 字节\n" +
	            "  - 总数据量: " + (encryptedSymmetricKey.length + encryptedCombinedData.length) + " 字节";
	        
	        stepResults.put("step5", result);
	        
	        // 在主输出区域也显示
	        outputArea.setText(
	            "步骤5完成：用B的公钥加密对称密钥K\n" +
	            "================================\n" +
	            "消息: " + currentMessage + "\n" +
	            "================================\n" +
	            result
	        );
	        
	        return true;
	        
	    } catch (Exception ex) {
	        String error = "❌ RSA加密失败: " + ex.getMessage();
	        stepResults.put("step5", error);
	        JOptionPane.showMessageDialog(this, error);
	        return false;
	    }
	}

	/**
	 * 步骤6: B解密并验证（修改版，返回是否成功）
	 */
	private boolean performStep6() {
	    if (privateKeyB == null || publicKeyA == null) {
	        String error = "❌ 失败：请先生成B的私钥和A的公钥！";
	        stepResults.put("step6", error);
	        JOptionPane.showMessageDialog(this, error);
	        return false;
	    }
	    
	    if (encryptedSymmetricKey == null || encryptedCombinedData == null) {
	        String error = "❌ 失败：请先完成步骤4和5！";
	        stepResults.put("step6", error);
	        JOptionPane.showMessageDialog(this, error);
	        return false;
	    }
	    
	    try {
	        StringBuilder result = new StringBuilder();
	        result.append("✅ 步骤完成\n");
	        result.append("原始消息: ").append(currentMessage).append("\n\n");
	        
	        // 1. B用自己的私钥解密对称密钥K
	        result.append("1. RSA解密对称密钥K:\n");
	        byte[] decryptedKeyBytes = RSAUtil.decrypt(encryptedSymmetricKey, privateKeyB);
	        String decryptedKey = new String(decryptedKeyBytes, "UTF-8");
	        result.append("   解密成功，密钥长度: ").append(decryptedKey.length()).append(" 字符\n");
	        boolean keyMatch = decryptedKey.equals(symmetricKey);
	        result.append("   密钥匹配: ").append(keyMatch ? "✅ 一致" : "❌ 不一致").append("\n\n");
	        
	        if (!keyMatch) {
	            result.append("⚠️ 警告：解密出的密钥与原始密钥不一致！\n\n");
	        }
	        
	        // 2. B用对称密钥K解密组合数据
	        result.append("2. 对称解密M||S:\n");
	        String algo = (String) symBox.getSelectedItem();
	        byte[] decryptedCombined;
	        
	        if ("AES".equals(algo)) {
	            decryptedCombined = SymmetricCrypto.decryptAES(encryptedCombinedData, decryptedKey);
	        } else {
	            decryptedCombined = SymmetricCrypto.decryptDES(encryptedCombinedData, decryptedKey);
	        }
	        
	        String combined = new String(decryptedCombined, "UTF-8");
	        result.append("   解密成功，数据长度: ").append(combined.length()).append(" 字符\n\n");
	        
	        // 3. 分离消息和签名
	        result.append("3. 分离消息M和签名S:\n");
	        MessageParts parts = MessageUtil.separateMessageAndSignature(combined);
	        result.append("   解密出的消息: ").append(parts.message).append("\n");
	        boolean messageMatch = parts.message.equals(currentMessage);
	        result.append("   消息匹配: ").append(messageMatch ? "✅ 一致" : "❌ 不一致").append("\n");
	        result.append("   签名S长度: ").append(parts.signature.length).append(" 字节\n\n");
	        
	        // 4. 计算Hash
	        result.append("4. 计算消息Hash:\n");
	        String hashAlgo = (String) hashBox.getSelectedItem();
	        String hash;
	        if ("MD5".equals(hashAlgo)) {
	            hash = HashUtil.md5(parts.message);
	        } else {
	            hash = HashUtil.sha256(parts.message);
	        }
	        result.append("   Hash算法: ").append(hashAlgo).append("\n");
	        result.append("   Hash值: ").append(hash.substring(0, Math.min(20, hash.length()))).append("...\n\n");
	        
	        // 5. 用A的公钥验证签名
	        result.append("5. 验证签名:\n");
	        boolean verified = SignUtil.verify(hash, parts.signature, publicKeyA);
	        
	        if (verified && keyMatch && messageMatch) {
	            result.append("   ✅ 所有验证通过！\n");
	            result.append("   ✓ 签名验证成功\n");
	            result.append("   ✓ 密钥匹配成功\n");
	            result.append("   ✓ 消息匹配成功\n");
	            result.append("   ✓ 完整通信流程验证完成");
	        } else {
	            result.append("   ❌ 验证失败！\n");
	            if (!verified) result.append("   ✗ 签名验证失败\n");
	            if (!keyMatch) result.append("   ✗ 密钥不匹配\n");
	            if (!messageMatch) result.append("   ✗ 消息不匹配\n");
	        }
	        
	        String finalResult = result.toString();
	        stepResults.put("step6", finalResult);
	        
	        // 在主输出区域显示完整结果
	        StringBuilder fullResult = new StringBuilder();
	        fullResult.append("步骤6完成：B解密并验证签名\n");
	        fullResult.append("================================\n");
	        fullResult.append("原始消息: ").append(currentMessage).append("\n");
	        fullResult.append("================================\n");
	        fullResult.append(finalResult);
	        fullResult.append("\n\n══════════════ 混合加密流程完成 ══════════════\n");
	        
	        if (verified && keyMatch && messageMatch) {
	            fullResult.append("\n🎉 恭喜！混合加密通信流程验证成功！\n");
	            fullResult.append("✓ 消息完整性保护\n");
	            fullResult.append("✓ 消息来源认证\n");
	            fullResult.append("✓ 数据机密性保护\n");
	            fullResult.append("✓ 对称密钥安全传输\n");
	        } else {
	            fullResult.append("\n⚠️ 验证失败，请检查密钥和流程\n");
	        }
	        
	        outputArea.setText(fullResult.toString());
	        
	        return verified && keyMatch && messageMatch;
	        
	    } catch (Exception ex) {
	        String error = "❌ 解密验证失败: " + ex.getMessage();
	        stepResults.put("step6", error);
	        JOptionPane.showMessageDialog(this, error);
	        return false;
	    }
	}
	
	/**
	 * 创建密钥管理面板（保持不变）
	 */
	private JPanel createKeyPanel() {
		// 保持原有密钥管理面板不变
		JPanel panel = new JPanel(new GridLayout(2, 1, 10, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		// A的密钥区域
		JPanel keyAPanel = new JPanel(new BorderLayout());
		keyAPanel.setBorder(BorderFactory.createTitledBorder("A的密钥对（发送方）"));

		JPanel keyAControls = new JPanel(new FlowLayout());
		JButton genKeyABtn = new JButton("生成新密钥");
		JButton saveKeyABtn = new JButton("保存私钥");
		JButton loadKeyABtn = new JButton("加载私钥");
		JButton showPubKeyABtn = new JButton("显示公钥");

		keyAControls.add(genKeyABtn);
		keyAControls.add(saveKeyABtn);
		keyAControls.add(loadKeyABtn);
		keyAControls.add(showPubKeyABtn);

		JPanel keyADisplay = new JPanel(new GridLayout(2, 1, 5, 5));
		pubKeyAText = new JTextArea(3, 60);
		pubKeyAText.setEditable(false);
		pubKeyAText.setBorder(BorderFactory.createTitledBorder("A的公钥（UKA）"));

		privKeyAText = new JTextArea(3, 60);
		privKeyAText.setEditable(false);
		privKeyAText.setBorder(BorderFactory.createTitledBorder("A的私钥（RKa）- 保密！"));

		keyADisplay.add(new JScrollPane(pubKeyAText));
		keyADisplay.add(new JScrollPane(privKeyAText));

		keyAPanel.add(keyAControls, BorderLayout.NORTH);
		keyAPanel.add(keyADisplay, BorderLayout.CENTER);

		// B的密钥区域
		JPanel keyBPanel = new JPanel(new BorderLayout());
		keyBPanel.setBorder(BorderFactory.createTitledBorder("B的密钥对（接收方）"));

		JPanel keyBControls = new JPanel(new FlowLayout());
		JButton genKeyBBtn = new JButton("生成新密钥");
		JButton saveKeyBBtn = new JButton("保存私钥");
		JButton loadKeyBBtn = new JButton("加载私钥");
		JButton showPubKeyBBtn = new JButton("显示公钥");

		keyBControls.add(genKeyBBtn);
		keyBControls.add(saveKeyBBtn);
		keyBControls.add(loadKeyBBtn);
		keyBControls.add(showPubKeyBBtn);

		JPanel keyBDisplay = new JPanel(new GridLayout(2, 1, 5, 5));
		pubKeyBText = new JTextArea(3, 60);
		pubKeyBText.setEditable(false);
		pubKeyBText.setBorder(BorderFactory.createTitledBorder("B的公钥（UKB）"));

		privKeyBText = new JTextArea(3, 60);
		privKeyBText.setEditable(false);
		privKeyBText.setBorder(BorderFactory.createTitledBorder("B的私钥（RKb）- 保密！"));

		keyBDisplay.add(new JScrollPane(pubKeyBText));
		keyBDisplay.add(new JScrollPane(privKeyBText));

		keyBPanel.add(keyBControls, BorderLayout.NORTH);
		keyBPanel.add(keyBDisplay, BorderLayout.CENTER);

		// 添加事件监听器
		setupKeyEventListeners(genKeyABtn, saveKeyABtn, loadKeyABtn, showPubKeyABtn, genKeyBBtn, saveKeyBBtn,
				loadKeyBBtn, showPubKeyBBtn);

		panel.add(keyAPanel);
		panel.add(keyBPanel);

		return panel;
	}


	/**
	 * 设置基础功能事件监听器
	 */
	private void setupBasicEventListeners(JButton genKeyBtn, JButton genKeyABtn, JButton genKeyBBtn, JButton hashBtn,
			JButton fileHashBtn, JButton encBtn, JButton decBtn, JButton fileEncBtn, JButton fileDecBtn,
			JButton signBtn, JButton verifyBtn, JButton fileSignBtn, JButton fileVerifyBtn) {

		// 生成对称密钥（用于基础功能）
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
			try {
				KeyPair kp = RSAUtil.generateKeyPair(2048);
				privateKeyA = kp.getPrivate();
				publicKeyA = kp.getPublic();

				// 更新显示
				pubKeyAText.setText("公钥（Base64）:\n" + Base64.getEncoder().encodeToString(publicKeyA.getEncoded()));
				privKeyAText.setText("私钥（Base64）:\n" + Base64.getEncoder().encodeToString(privateKeyA.getEncoded()));

				JOptionPane.showMessageDialog(this, "✅ A的密钥对生成成功！");
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this, "❌ 生成失败: " + ex.getMessage());
			}
		});

		// 生成B的密钥对
		genKeyBBtn.addActionListener(e -> {
			try {
				KeyPair kp = RSAUtil.generateKeyPair(2048);
				privateKeyB = kp.getPrivate();
				publicKeyB = kp.getPublic();

				// 更新显示
				pubKeyBText.setText("公钥（Base64）:\n" + Base64.getEncoder().encodeToString(publicKeyB.getEncoded()));
				privKeyBText.setText("私钥（Base64）:\n" + Base64.getEncoder().encodeToString(privateKeyB.getEncoded()));

				JOptionPane.showMessageDialog(this, "✅ B的密钥对生成成功！");
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this, "❌ 生成失败: " + ex.getMessage());
			}
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
			outputArea.setText("Hash值（" + algo + "）:\n" + hash);
		});

        // 文件Hash
        fileHashBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                File file = chooser.getSelectedFile();
                byte[] data = FileUtil.readFile(file);
                
                String algo = (String) hashBox.getSelectedItem();
                String hash;
                if ("MD5".equals(algo)) {
                    hash = HashUtil.md5(data);
                } else {
                    hash = HashUtil.sha256(data);
                }
                outputArea.setText("文件Hash (" + algo + "):\n" + hash);
            }
        });

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

				outputArea.setText("加密结果（Hex）:\n" + bytesToHex(cipher));
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this, "❌ 加密失败: " + ex.getMessage());
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

				outputArea.setText("解密结果:\n" + new String(plain, "UTF-8"));
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this, "❌ 解密失败: " + ex.getMessage());
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
					JOptionPane.showMessageDialog(this, "✅ 文件已加密: " + save.getName());
				} catch (Exception ex) {
					JOptionPane.showMessageDialog(this, "❌ 加密失败: " + ex.getMessage());
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
					JOptionPane.showMessageDialog(this, "✅ 文件已解密: " + save.getName());
				} catch (Exception ex) {
					JOptionPane.showMessageDialog(this, "❌ 解密失败: " + ex.getMessage());
				}
			}
		});

		// 签名（基础版）
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
				signatureArea.setText(Base64.getEncoder().encodeToString(sign));
				outputArea.setText("签名完成（" + algo + "）:\n" + Base64.getEncoder().encodeToString(sign).substring(0,
						Math.min(50, Base64.getEncoder().encodeToString(sign).length())) + "...");
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this, "❌ 签名失败: " + ex.getMessage());
			}
		});

		// 验证签名（基础版）
		verifyBtn.addActionListener(e -> {
			if (publicKeyA == null) {
				JOptionPane.showMessageDialog(this, "请先生成A的密钥对！");
				return;
			}

			String text = inputArea.getText();
			String signBase64 = signatureArea.getText();
			if (text.isEmpty() || signBase64.isEmpty()) {
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
				byte[] signature = Base64.getDecoder().decode(signBase64);
				boolean ok = SignUtil.verify(hash, signature, publicKeyA);
				outputArea.setText(ok ? "✅ 签名验证成功" : "❌ 签名验证失败");
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this, "❌ 验证失败: " + ex.getMessage());
			}
		});
		
	    // 文件签名功能
	    fileSignBtn.addActionListener(e -> {
	        if (privateKeyA == null) {
	            JOptionPane.showMessageDialog(this, "请先生成A的密钥对！");
	            return;
	        }
	        
	        JFileChooser chooser = new JFileChooser();
	        chooser.setDialogTitle("选择要签名的文件");
	        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
	            File file = chooser.getSelectedFile();
	            
	            try {
	                // 读取文件内容
	                byte[] fileData = FileUtil.readFile(file);
	                
	                // 计算文件的Hash
	                String algo = (String) hashBox.getSelectedItem();
	                String hash;
	                if ("MD5".equals(algo)) {
	                    hash = HashUtil.md5(fileData);
	                } else {
	                    hash = HashUtil.sha256(fileData);
	                }
	                
	                // 用A的私钥签名
	                byte[] signature = SignUtil.sign(hash, privateKeyA);
	                String signatureBase64 = Base64.getEncoder().encodeToString(signature);
	                
	                // 保存签名到文件（原文件名.sig）
	                File sigFile = new File(file.getParent(), file.getName() + ".sig");
	                FileUtil.saveFile(signatureBase64.getBytes("UTF-8"), sigFile);
	                
	                // 同时保存签名信息到文本文件，便于查看
	                File sigInfoFile = new File(file.getParent(), file.getName() + "_signature.txt");
	                String sigInfo = 
	                    "文件签名信息\n" +
	                    "=============\n" +
	                    "文件名: " + file.getName() + "\n" +
	                    "文件大小: " + file.length() + " 字节\n" +
	                    "Hash算法: " + algo + "\n" +
	                    "Hash值: " + hash + "\n" +
	                    "签名时间: " + new java.util.Date() + "\n" +
	                    "签名长度: " + signature.length + " 字节\n" +
	                    "签名(Base64): " + signatureBase64 + "\n" +
	                    "签名文件: " + sigFile.getName();
	                
	                FileUtil.saveFile(sigInfo.getBytes("UTF-8"), sigInfoFile);
	                
	                // 显示结果
	                outputArea.setText(
	                    "✅ 文件签名完成\n" +
	                    "文件: " + file.getName() + "\n" +
	                    "文件大小: " + file.length() + " 字节\n" +
	                    "Hash算法: " + algo + "\n" +
	                    "Hash值: " + hash.substring(0, Math.min(30, hash.length())) + "...\n" +
	                    "签名长度: " + signature.length + " 字节\n" +
	                    "签名文件: " + sigFile.getName() + "\n" +
	                    "签名信息文件: " + sigInfoFile.getName()
	                );
	                
	                JOptionPane.showMessageDialog(this, 
	                    "<html><div style='text-align: center;'>" +
	                    "<h3>✅ 文件签名完成</h3>" +
	                    "<p>文件: " + file.getName() + "</p>" +
	                    "<p>签名文件: " + sigFile.getName() + "</p>" +
	                    "</div></html>");
	                
	            } catch (Exception ex) {
	                JOptionPane.showMessageDialog(this, "❌ 文件签名失败: " + ex.getMessage());
	            }
	        }
	    });
	    
	    // 验证文件签名功能
	    fileVerifyBtn.addActionListener(e -> {
	        if (publicKeyA == null) {
	            JOptionPane.showMessageDialog(this, "请先生成A的密钥对！");
	            return;
	        }
	        
	        // 第一步：选择原始文件
	        JFileChooser fileChooser = new JFileChooser();
	        fileChooser.setDialogTitle("选择要验证的原始文件");
	        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
	            File originalFile = fileChooser.getSelectedFile();
	            
	            // 第二步：选择签名文件（自动建议文件名.sig）
	            JFileChooser sigChooser = new JFileChooser(originalFile.getParent());
	            File suggestedSigFile = new File(originalFile.getParent(), originalFile.getName() + ".sig");
	            if (suggestedSigFile.exists()) {
	                sigChooser.setSelectedFile(suggestedSigFile);
	            }
	            sigChooser.setDialogTitle("选择签名文件（通常为" + originalFile.getName() + ".sig）");
	            
	            if (sigChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
	                File sigFile = sigChooser.getSelectedFile();
	                
	                try {
	                    // 读取原始文件内容
	                    byte[] fileData = FileUtil.readFile(originalFile);
	                    
	                    // 计算文件的Hash
	                    String algo = (String) hashBox.getSelectedItem();
	                    String hash;
	                    if ("MD5".equals(algo)) {
	                        hash = HashUtil.md5(fileData);
	                    } else {
	                        hash = HashUtil.sha256(fileData);
	                    }
	                    
	                    // 读取签名文件
	                    byte[] sigData = FileUtil.readFile(sigFile);
	                    String signatureBase64 = new String(sigData, "UTF-8").trim();
	                    byte[] signature = Base64.getDecoder().decode(signatureBase64);
	                    
	                    // 用A的公钥验证签名
	                    boolean verified = SignUtil.verify(hash, signature, publicKeyA);
	                    
	                    // 构建详细结果
	                    StringBuilder result = new StringBuilder();
	                    result.append("🔍 文件签名验证结果\n");
	                    result.append("==================\n\n");
	                    result.append("原始文件: ").append(originalFile.getName()).append("\n");
	                    result.append("文件大小: ").append(originalFile.length()).append(" 字节\n");
	                    result.append("签名文件: ").append(sigFile.getName()).append("\n");
	                    result.append("Hash算法: ").append(algo).append("\n");
	                    result.append("Hash值: ").append(hash).append("\n\n");
	                    
	                    if (verified) {
	                        result.append("✅ 签名验证成功！\n\n");
	                        result.append("验证结论：\n");
	                        result.append("✓ 文件确实来自A（签名者）\n");
	                        result.append("✓ 文件在签名后未被篡改\n");
	                        result.append("✓ 文件的完整性和真实性得到保证\n");
	                        result.append("✓ 可以信任此文件\n");
	                        
	                        // 检查是否有签名信息文件
	                        File sigInfoFile = new File(originalFile.getParent(), originalFile.getName() + "_signature.txt");
	                        if (sigInfoFile.exists()) {
	                            byte[] infoData = FileUtil.readFile(sigInfoFile);
	                            String info = new String(infoData, "UTF-8");
	                            result.append("\n📄 签名信息文件内容：\n");
	                            result.append(info);
	                        }
	                    } else {
	                        result.append("❌ 签名验证失败！\n\n");
	                        result.append("可能的原因：\n");
	                        result.append("✗ 文件在签名后被篡改\n");
	                        result.append("✗ 签名者不是A\n");
	                        result.append("✗ 签名文件损坏或不匹配\n");
	                        result.append("✗ 使用的公钥不正确\n");
	                        result.append("\n⚠️ 警告：此文件可能不可信！");
	                    }
	                    
	                    outputArea.setText(result.toString());
	                    
	                    // 弹出验证结果对话框
	                    if (verified) {
	                        JOptionPane.showMessageDialog(this,
	                            "<html><div style='text-align: center;'>" +
	                            "<h3 style='color: green;'>✅ 签名验证成功</h3>" +
	                            "<p>文件: " + originalFile.getName() + "</p>" +
	                            "<p>文件完整性得到保证</p>" +
	                            "</div></html>");
	                    } else {
	                        JOptionPane.showMessageDialog(this,
	                            "<html><div style='text-align: center;'>" +
	                            "<h3 style='color: red;'>❌ 签名验证失败</h3>" +
	                            "<p>文件: " + originalFile.getName() + "</p>" +
	                            "<p>文件可能被篡改</p>" +
	                            "</div></html>");
	                    }
	                    
	                } catch (Exception ex) {
	                    JOptionPane.showMessageDialog(this, "❌ 验证文件签名失败: " + ex.getMessage());
	                }
	            }
	        }
	    });
	}

	/**
	 * 设置密钥管理事件监听器（保持不变）
	 */
	private void setupKeyEventListeners(JButton genKeyABtn, JButton saveKeyABtn, JButton loadKeyABtn,
			JButton showPubKeyABtn, JButton genKeyBBtn, JButton saveKeyBBtn, JButton loadKeyBBtn,
			JButton showPubKeyBBtn) {

		// 生成A的密钥
		genKeyABtn.addActionListener(e -> {
			try {
				KeyPair kp = RSAUtil.generateKeyPair(2048);
				privateKeyA = kp.getPrivate();
				publicKeyA = kp.getPublic();

				pubKeyAText.setText("公钥（Base64）:\n" + Base64.getEncoder().encodeToString(publicKeyA.getEncoded()));
				privKeyAText.setText("私钥（Base64）:\n" + Base64.getEncoder().encodeToString(privateKeyA.getEncoded()));

				JOptionPane.showMessageDialog(this, "✅ A的密钥对生成成功！");
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this, "❌ 生成失败: " + ex.getMessage());
			}
		});

		// 显示A的公钥详情
		showPubKeyABtn.addActionListener(e -> {
			if (publicKeyA == null) {
				JOptionPane.showMessageDialog(this, "请先生成A的密钥对！");
				return;
			}

			String pubKeyStr = Base64.getEncoder().encodeToString(publicKeyA.getEncoded());
			JTextArea detailArea = new JTextArea(pubKeyStr);
			detailArea.setEditable(false);
			JScrollPane scrollPane = new JScrollPane(detailArea);
			scrollPane.setPreferredSize(new Dimension(600, 400));

			JOptionPane.showMessageDialog(this, scrollPane, "A的公钥详情", JOptionPane.INFORMATION_MESSAGE);
		});

		// 生成B的密钥
		genKeyBBtn.addActionListener(e -> {
			try {
				KeyPair kp = RSAUtil.generateKeyPair(2048);
				privateKeyB = kp.getPrivate();
				publicKeyB = kp.getPublic();

				pubKeyBText.setText("公钥（Base64）:\n" + Base64.getEncoder().encodeToString(publicKeyB.getEncoded()));
				privKeyBText.setText("私钥（Base64）:\n" + Base64.getEncoder().encodeToString(privateKeyB.getEncoded()));

				JOptionPane.showMessageDialog(this, "✅ B的密钥对生成成功！");
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this, "❌ 生成失败: " + ex.getMessage());
			}
		});

		// 显示B的公钥详情
		showPubKeyBBtn.addActionListener(e -> {
			if (publicKeyB == null) {
				JOptionPane.showMessageDialog(this, "请先生成B的密钥对！");
				return;
			}

			String pubKeyStr = Base64.getEncoder().encodeToString(publicKeyB.getEncoded());
			JTextArea detailArea = new JTextArea(pubKeyStr);
			detailArea.setEditable(false);
			JScrollPane scrollPane = new JScrollPane(detailArea);
			scrollPane.setPreferredSize(new Dimension(600, 400));

			JOptionPane.showMessageDialog(this, scrollPane, "B的公钥详情", JOptionPane.INFORMATION_MESSAGE);
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
			MainFrame frame = new MainFrame();
			frame.setExtendedState(JFrame.MAXIMIZED_BOTH);
		});
	}
}