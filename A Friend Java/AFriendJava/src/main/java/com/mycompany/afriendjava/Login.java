package com.mycompany.afriendjava;

import java.awt.Color;
import java.util.Timer;
import java.util.TimerTask;
import java.awt.GraphicsDevice;
import java.awt.GraphicsEnvironment;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.io.IOException;
import ui.customcomponents.*;
import javax.swing.JTextField;
import javax.swing.UIManager;

import com.google.inject.spi.RequireAtInjectOnConstructorsOption;

public class Login extends javax.swing.JFrame {

    private TextPrompt usernamePrompt;
    private TextPrompt passwordPrompt;

    public Login() {
        // set look and feel
        try {
            // set look and feel to java default look and feel
            UIManager.setLookAndFeel(UIManager.getInstalledLookAndFeels()[0].getClassName());
        } catch (Exception e){
            System.out.println(e.getMessage());
        }
        initComponents();
        setLocationRelativeTo(null);
        addPlaceholderStyle(textFieldUsername);
        addPlaceholderStyle(pFieldPassword);
    }

    private void initComponents() {

        labelTitle = new javax.swing.JLabel();
        textFieldUsername = new javax.swing.JTextField();
        pFieldPassword = new javax.swing.JPasswordField();
        buttonLogIn = new javax.swing.JButton();
        buttonSignUp = new javax.swing.JButton();
        buttonExit = new javax.swing.JButton();
        labelWarning = new javax.swing.JLabel();
        labelForgotPassword = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setAutoRequestFocus(false);
        setResizable(false);
        setSize(new java.awt.Dimension(418, 662));
        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowOpened(java.awt.event.WindowEvent evt) {
                load();
            }
        });
        setUndecorated(true);

        labelTitle.setFont(new java.awt.Font("Microsoft Sans Serif", 0, 36)); // NOI18N
        labelTitle.setForeground(new java.awt.Color(37, 75, 133));
        labelTitle.setText("Log In");

        textFieldUsername.setFont(new java.awt.Font("Microsoft Sans Serif", 0, 14)); // NOI18N
        textFieldUsername.setText("");
        textFieldUsername.setToolTipText("");
        textFieldUsername.setName(""); // NOI18N
        textFieldUsername.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                textFieldUsernameFocusGained(evt);
            }
            public void focusLost(java.awt.event.FocusEvent evt) {
                textFieldUsernameFocusLost(evt);
            }
        });
        textFieldUsername.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                textFieldUsernameKeyPressed(evt);
            }
        });
        usernamePrompt = new TextPrompt("Username", textFieldUsername);

        pFieldPassword.setFont(new java.awt.Font("Microsoft Sans Serif", 0, 14)); // NOI18N
        pFieldPassword.setText("");
        pFieldPassword.setEchoChar('\u0000');
        pFieldPassword.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                pFieldPasswordFocusGained(evt);
            }
            public void focusLost(java.awt.event.FocusEvent evt) {
                pFieldPasswordFocusLost(evt);
            }
        });
        pFieldPassword.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                pFieldPasswordKeyPressed(evt);
            }
        });
        pFieldPassword.setEchoChar('\u25CF');
        passwordPrompt = new TextPrompt("Password", pFieldPassword);

        buttonLogIn.setBackground(new java.awt.Color(37, 75, 133));
        buttonLogIn.setFont(new java.awt.Font("Microsoft Sans Serif", 0, 18)); // NOI18N
        buttonLogIn.setForeground(new java.awt.Color(255, 255, 255));
        buttonLogIn.setText("LOG IN");
        buttonLogIn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonLogInActionPerformed(evt);
            }
        });

        buttonSignUp.setBackground(new java.awt.Color(90, 198, 140));
        buttonSignUp.setFont(new java.awt.Font("Microsoft Sans Serif", 0, 18)); // NOI18N
        buttonSignUp.setForeground(new java.awt.Color(255, 255, 255));
        buttonSignUp.setText("SIGN UP");
        buttonSignUp.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                buttonSignUpMouseClicked(evt);
            }
        });

        buttonExit.setBackground(new java.awt.Color(213, 54, 41));
        buttonExit.setFont(new java.awt.Font("Microsoft Sans Serif", 0, 18)); // NOI18N
        buttonExit.setForeground(new java.awt.Color(255, 255, 255));
        buttonExit.setText("EXIT");
        buttonExit.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                buttonExitMouseClicked(evt);
            }
        });

        labelWarning.setFont(new java.awt.Font("Microsoft Sans Serif", 0, 14)); // NOI18N
        labelWarning.setForeground(new java.awt.Color(255, 0, 0));
        labelWarning.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);

        labelForgotPassword.setFont(new java.awt.Font("Microsoft Sans Serif", 0, 14)); // NOI18N
        labelForgotPassword.setForeground(new java.awt.Color(37, 75, 133));
        labelForgotPassword.setText("Forgot Password?");
        labelForgotPassword.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                labelForgotPasswordMouseClicked(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(98, Short.MAX_VALUE)
                .addComponent(labelTitle, javax.swing.GroupLayout.PREFERRED_SIZE, 107, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(90, 90, 90))
            .addGroup(layout.createSequentialGroup()
                .addGap(26, 26, 26)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(buttonExit, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(buttonSignUp, javax.swing.GroupLayout.DEFAULT_SIZE, 244, Short.MAX_VALUE)
                    .addComponent(buttonLogIn, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(textFieldUsername)
                    .addComponent(pFieldPassword)
                    .addComponent(labelForgotPassword, javax.swing.GroupLayout.Alignment.TRAILING))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(labelWarning, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(58, 58, 58)
                .addComponent(labelTitle, javax.swing.GroupLayout.PREFERRED_SIZE, 50, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(31, 31, 31)
                .addComponent(textFieldUsername, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(pFieldPassword, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(buttonLogIn, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(labelForgotPassword)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 37, Short.MAX_VALUE)
                .addComponent(labelWarning, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(buttonSignUp, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(buttonExit, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(51, Short.MAX_VALUE))
        );

        pack();
    }

    protected void buttonLogInActionPerformed(ActionEvent evt) {
        buttonLogInMouseClicked();
    }

    protected void load() {
        this.setTitle("\t");
        this.setAlwaysOnTop(true);
        this.requestFocus();
        java.awt.EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                toFront();
                repaint();
                setAlwaysOnTop(false);
            }
        });
    }
    private Timer timerClosing = new Timer();

    private Timer timerDisconnect = new Timer();
    
    private void timerDisconnect_Tick(){
        if ((labelWarning.getText() == "" || labelWarning.getText() == "Somthing is missing!") && this.isVisible()){
            try {
                AFriendClient.dos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                AFriendClient.dis.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                AFriendClient.client.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            labelWarning.setText("Cannot connect to server");
        }
    }

    private void timerClosing_Tick(){
        MainUI frm = new MainUI();
        /*
        GraphicsDevice gd = GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice();
        int width = gd.getDisplayMode().getWidth();
        int height = gd.getDisplayMode().getHeight();
        frm.setLocation(width / 4, height / 4);
        */
        this.ResetTexts();
        //frm.setVisible(true);
        this.setVisible(false);
        Program.mainform = frm;
        Thread thread = new Thread(new Runnable(){
            @Override
            public void run(){
                AFriendClient.executeClient();
            }
        });
        thread.start();
    }


    private void ResetTexts() {
        textFieldUsername.setText("");
        pFieldPassword.setText("");
        labelWarning.setText("");
    }


    public synchronized void setLabelTitleText(String text) {
        labelTitle.setText(text);
    }

    public void addPlaceholderStyle(JTextField textField) {
        textField.setForeground(Color.GRAY);
    }

    public void removePlaceholderStyle(JTextField textField) {
        textField.setForeground(Color.BLACK);
    }

    private boolean IsEmptyTextField() {
        if (textFieldUsername.getText().length() == 0 || textFieldUsername.getText().equals("Username") || (pFieldPassword.getPassword().toString().length() == 0 || pFieldPassword.getPassword().toString().equals("Password"))) {
            return true;
        } else {
            return false;
        }
    }
    

    protected void pFieldPasswordKeyPressed(KeyEvent evt) {
        // check if key is ENTER
        if (evt.getKeyCode() == KeyEvent.VK_ENTER) {
            buttonLogIn.doClick();
        }
    }

    protected void textFieldUsernameKeyPressed(KeyEvent evt) {
        // check if key is ENTER
        if (evt.getKeyCode() == KeyEvent.VK_ENTER) {
            buttonLogIn.doClick();
        }
        
    }

    private void textFieldUsernameFocusGained(java.awt.event.FocusEvent evt) {
        if (labelWarning.getText() == "" || labelWarning.getText() == "Something is missing!")
        {
            return;
        }
        this.ResetTexts();
    }

    private void pFieldPasswordFocusGained(java.awt.event.FocusEvent evt) {
        if (labelWarning.getText() == "" || labelWarning.getText() == "Something is missing!")
        {
            return;
        }
        this.ResetTexts();
    }

    private void textFieldUsernameFocusLost(java.awt.event.FocusEvent evt) {
        return;
    }

    private void pFieldPasswordFocusLost(java.awt.event.FocusEvent evt) {
        return;
    }

    private void buttonLogInMouseClicked() {
        timerDisconnect.schedule(new TimerTask()
        {
            @Override
            public void run() {
                timerDisconnect_Tick();
            }
        }, 19000);
        if (IsEmptyTextField()) {
            labelWarning.setText("Please complete your login information.");
        }
        else {
            if (checkInvalidUsernameCharacter()){
                labelWarning.setText("Username contains invalid character.");
                return;
            }
            else {
                if (checkInvalidPasswordCharacter()){
                    labelWarning.setText("Password contains invalid characters");
                    return;
                }
                else {
                    if (!correctPassword()){
                        labelWarning.setText("Incorrect password.");
                        return;
                    }
                }
            }
        }
        labelWarning.setText("You have logged in successfully".toUpperCase());
        labelWarning.setForeground(new Color(37, 75, 133));
        timerClosing.schedule(
            new TimerTask()
            {
                @Override
                public void run() {
                    timerClosing_Tick();
                }
            }
            , 1000);
    }

    private boolean correctPassword() {
        boolean res = AFriendClient.tryLogin(textFieldUsername.getText(), new String(pFieldPassword.getPassword()));
        AFriendClient.loginResult = true;
        return res;
    }

    private boolean checkInvalidPasswordCharacter() {
        for(char i : pFieldPassword.getPassword()){
            if (!(i == 33 || i > 34 && i < 38 || i >= 42 && i <= 43 || i == 45 || i >= 48 && i <= 57 || i >= 64 && i <= 90 || i == 94 || i == 95 || i >= 97 && i <= 122))
            {
                return true;
            }
        }
        return false;
    }

    private boolean checkInvalidUsernameCharacter() {
        for(char i : textFieldUsername.getText().toCharArray()){
            if (!(i >= 48 && i <= 57 || i >= 65 && i <= 90 || i >= 97 && i <= 122 || i == 95))
            {
                return true;
            }
        }
        return false;
    }

    private void labelForgotPasswordMouseClicked(java.awt.event.MouseEvent evt) {
        setVisible(false);
        ResetPassword resetPassword = new ResetPassword();
        resetPassword.setVisible(true);
    }

    private void buttonSignUpMouseClicked(java.awt.event.MouseEvent evt) {
        setVisible(false);
        SignUp signUp = new SignUp();
        signUp.setVisible(true);
    }

    private void buttonExitMouseClicked(java.awt.event.MouseEvent evt) {
        //this.dispose();
        System.exit(0);
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Login.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Login.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Login.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Login.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Login().setVisible(true);
            }
        });
    }

    private javax.swing.JButton buttonExit;
    private javax.swing.JButton buttonLogIn;
    private javax.swing.JButton buttonSignUp;
    private javax.swing.JLabel labelForgotPassword;
    private javax.swing.JLabel labelTitle;
    private javax.swing.JLabel labelWarning;
    private javax.swing.JPasswordField pFieldPassword;
    private javax.swing.JTextField textFieldUsername;
}
