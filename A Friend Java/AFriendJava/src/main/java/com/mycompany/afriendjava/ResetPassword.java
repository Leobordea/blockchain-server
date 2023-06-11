package com.mycompany.afriendjava;

import java.awt.Color;
import javax.swing.JTextField;

public class ResetPassword extends javax.swing.JFrame {

    public ResetPassword() {
        initComponents();
        setLocationRelativeTo(null);
        addPlaceholderStyle(pFieldNewPassword);
        addPlaceholderStyle(pFieldConfirmPassword);
    }

    public void addPlaceholderStyle(JTextField textField) {
        textField.setForeground(Color.GRAY);
    }

    public void removePlaceholderStyle(JTextField textField) {
        textField.setForeground(Color.BLACK);
    }

    private boolean IsEmptyTextField() {
        if (pFieldNewPassword.getPassword().toString().length() == 0 || pFieldNewPassword.getPassword().toString().equals("Create New Password") || (pFieldConfirmPassword.getPassword().toString().length() == 0 || pFieldConfirmPassword.getPassword().toString().equals("Create New Password"))) {
            return true;
        } else {
            return false;
        }
    }

    private boolean MatchPassword() {
        if (pFieldNewPassword.getPassword().toString().equals(pFieldConfirmPassword.getPassword().toString())) {
            return true;
        } else {
            return false;
        }
    }

    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        labelTitle = new javax.swing.JLabel();
        buttonResetPassword = new javax.swing.JButton();
        pFieldNewPassword = new javax.swing.JPasswordField();
        pFieldConfirmPassword = new javax.swing.JPasswordField();
        labelWarning = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setAutoRequestFocus(false);
        setResizable(false);

        jPanel1.setBackground(new java.awt.Color(255, 255, 255));

        labelTitle.setFont(new java.awt.Font("Microsoft Sans Serif", 1, 30)); // NOI18N
        labelTitle.setForeground(new java.awt.Color(37, 75, 133));
        labelTitle.setText(" Reset Password");

        buttonResetPassword.setBackground(new java.awt.Color(37, 75, 133));
        buttonResetPassword.setFont(new java.awt.Font("Microsoft Sans Serif", 1, 14)); // NOI18N
        buttonResetPassword.setForeground(new java.awt.Color(255, 255, 255));
        buttonResetPassword.setText("Reset Password");
        buttonResetPassword.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                buttonResetPasswordMouseClicked(evt);
            }
        });

        pFieldNewPassword.setFont(new java.awt.Font("Microsoft Sans Serif", 0, 14)); // NOI18N
        pFieldNewPassword.setText("Create New Password");
        pFieldNewPassword.setEchoChar('\u0000');
        pFieldNewPassword.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                pFieldNewPasswordFocusGained(evt);
            }
            public void focusLost(java.awt.event.FocusEvent evt) {
                pFieldNewPasswordFocusLost(evt);
            }
        });

        pFieldConfirmPassword.setFont(new java.awt.Font("Microsoft Sans Serif", 0, 14)); // NOI18N
        pFieldConfirmPassword.setText("Confirm Password");
        pFieldConfirmPassword.setEchoChar('\u0000');
        pFieldConfirmPassword.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                pFieldConfirmPasswordFocusGained(evt);
            }
            public void focusLost(java.awt.event.FocusEvent evt) {
                pFieldConfirmPasswordFocusLost(evt);
            }
        });

        labelWarning.setFont(new java.awt.Font("Microsoft Sans Serif", 0, 14)); // NOI18N
        labelWarning.setForeground(new java.awt.Color(255, 0, 0));
        labelWarning.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                .addContainerGap(26, Short.MAX_VALUE)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(labelTitle)
                    .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                        .addComponent(pFieldNewPassword, javax.swing.GroupLayout.PREFERRED_SIZE, 244, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(buttonResetPassword, javax.swing.GroupLayout.PREFERRED_SIZE, 244, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(pFieldConfirmPassword, javax.swing.GroupLayout.PREFERRED_SIZE, 244, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(25, 25, 25))
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(labelWarning, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                .addGap(26, 26, 26)
                .addComponent(labelTitle)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(pFieldNewPassword, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(pFieldConfirmPassword, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(buttonResetPassword, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(labelWarning, javax.swing.GroupLayout.PREFERRED_SIZE, 16, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(14, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void pFieldConfirmPasswordFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_pFieldConfirmPasswordFocusLost
        if (pFieldConfirmPassword.getPassword().toString().length() == 0) {
            addPlaceholderStyle(pFieldConfirmPassword);
            pFieldConfirmPassword.setText("Confirm Password");
            pFieldConfirmPassword.setEchoChar('\u0000');
        }
    }//GEN-LAST:event_pFieldConfirmPasswordFocusLost

    private void pFieldConfirmPasswordFocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_pFieldConfirmPasswordFocusGained
        if (pFieldConfirmPassword.getPassword().toString().equals("Confirm Password")) {
            pFieldConfirmPassword.setText(null);
            pFieldConfirmPassword.requestFocus();
            pFieldConfirmPassword.setEchoChar('\u25CF');
            removePlaceholderStyle(pFieldConfirmPassword);
        }
    }//GEN-LAST:event_pFieldConfirmPasswordFocusGained

    private void pFieldNewPasswordFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_pFieldNewPasswordFocusLost
        if (pFieldNewPassword.getPassword().toString().length() == 0) {
            addPlaceholderStyle(pFieldNewPassword);
            pFieldNewPassword.setText("Create New Password");
            pFieldNewPassword.setEchoChar('\u0000');
        }
    }//GEN-LAST:event_pFieldNewPasswordFocusLost

    private void pFieldNewPasswordFocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_pFieldNewPasswordFocusGained
        if (pFieldNewPassword.getPassword().toString().equals("Create New Password")) {
            pFieldNewPassword.setText(null);
            pFieldNewPassword.requestFocus();
            pFieldNewPassword.setEchoChar('\u25CF');
            removePlaceholderStyle(pFieldNewPassword);
        }
    }//GEN-LAST:event_pFieldNewPasswordFocusGained

    private void buttonResetPasswordMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_buttonResetPasswordMouseClicked
        if (IsEmptyTextField())
        labelWarning.setText("Please complete your password.");
        else if (!MatchPassword())
        labelWarning.setText("Passwords do NOT match.");
        else {
            dispose();
            Login login = new Login();
            login.setVisible(true);
        }
    }//GEN-LAST:event_buttonResetPasswordMouseClicked

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
            java.util.logging.Logger.getLogger(ResetPassword.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(ResetPassword.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(ResetPassword.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(ResetPassword.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new ResetPassword().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton buttonResetPassword;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JLabel labelTitle;
    private javax.swing.JLabel labelWarning;
    private javax.swing.JPasswordField pFieldConfirmPassword;
    private javax.swing.JPasswordField pFieldNewPassword;
    // End of variables declaration//GEN-END:variables
}
