/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JPanel.java to edit this template
 */
package ui.customcomponents;

import java.awt.Color;
import java.awt.Font;
import java.awt.Insets;
import java.awt.event.ComponentEvent;
import java.awt.event.MouseEvent;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import javax.imageio.ImageIO;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.border.EmptyBorder;

import com.mycompany.afriendjava.AFile;
import com.mycompany.afriendjava.AFriendClient;
import com.mycompany.afriendjava.MessageObject;
import com.mycompany.afriendjava.Tools;

import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.FlowLayout;
import java.awt.Dimension;
import java.awt.Image;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;
import java.util.UUID;

/**
 *
 * @author maima
 */
public class AFChatItem extends javax.swing.JPanel {
    public static int DELETEICON_WIDTH = 40;
    public static int DELETEICON_HEIGHT = 40; 
    public static String TESTSTRING = "\ud83d\udc36";

    public Image deleteIcon = (new ImageIcon(getClass().getResource("deleteIcon.png"))).getImage();

    public MessageObject messageObject;
    public BufferedImage image;
    private int maxMessageWidth = -1;


    private boolean showDetail;
    public boolean getShowDetail()  { return showDetail; }
    public void setShowDetail(boolean showDetail) { 
        this.showDetail = showDetail; 
        topPanel.setVisible(showDetail);
        this.revalidate();
        this.repaint();
        /* 
        if (showDetail){
            this.setSize(this.getSize().width, 5 + topPanel.getSize().height + bottomPanel.getSize().height);
            //this.invalidate();
        }
        else{
            this.setSize(this.getSize().width, 5 + bottomPanel.getSize().height);
            //this.invalidate();
        }*/
    }

    public Color getBackgroundColor(){
        return panelBody.backColor;
    }
    public void setBackgroundColor(Color color){
        if (messageObject.type == 0 || messageObject.type == 3){
            textBody.setBackground(color);
        }
        panelBody.backColor = color;
        panelBody.repaint();
    }

    public static void main(String[] args){
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                JFrame frame = new JFrame();
                frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                frame.setBounds(100, 100, 500, 500);
                //frame.setLayout(null);
                //frame.setLayout(new BoxLayout(frame.getContentPane(), BoxLayout.Y_AXIS));
                
                JPanel panel = new JPanel();
                panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

                JScrollPane scroll = new JScrollPane(panel);
                scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
                
                panel.add(Box.createVerticalGlue());
                AFChatItem chatItem2 = new AFChatItem(TESTSTRING, true);
                chatItem2.updateDateTime();
                panel.add(ChatLayout.createChatItemBox(chatItem2));
                AFChatItem chatItem3 = new AFChatItem(TESTSTRING, false);
                panel.add(ChatLayout.createChatItemBox(chatItem3));
                AFChatItem chatItem4 = new AFChatItem(TESTSTRING + "432", true);
                panel.add(ChatLayout.createChatItemBox(chatItem4), 1);
                
                frame.add(scroll);
                frame.setVisible(true);
            }
        });
    }

    public void changeTextUpload(byte percent){
        authorBody.setText(percent + "%");
        authorBody.setForeground(Color.blue);
        if (percent == 100){
            authorBody.setText("DONE");
        }
    }

    private String originalFileName;
    private long originalFileSize;
    private Timer timer;
    private String timetext;


    public void startTimer(String file, long size){
        originalFileName = file;
        originalFileSize = size;
        authorBody.setForeground(Color.green);
        timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                try{
                    long left = AFriendClient.files.get(originalFileName).size;
                    authorBody.setText(100*(originalFileSize - left / 1048576) / originalFileSize + "%");
                    if (left == 0){
                        authorBody.setText("DONE");
                        timer.cancel();
                    }
                }
                catch (NullPointerException npe){
                    authorBody.setText("DONE");
                    timer.cancel();
                }
                catch(Exception e){
                    authorBody.setText(timetext);
                    timer.cancel();
                }
            }
        }, 0, 1000);
    }


    public AFChatItem(MessageObject messageObject){
        this.messageObject = messageObject;
        this.isMine = messageObject.sender? messageObject.id2.equals(AFriendClient.user.id) : messageObject.id1.equals(AFriendClient.user.id);
        //System.out.println(this.isMine);
        this.text = messageObject.message;

        initComponents();

        if (!this.isMine){
            this.setBackground(new Color(215, 244, 241));
        }

        if (this.messageObject.type == 3){
            textBody.setBackground(Color.decode("#FFFF00"));
            textBody.setForeground(Color.decode("#000000"));
            panelBody.setBackground(Color.decode("#FFFF00"));
            //double click event on textBody
            textBody.addMouseListener(new java.awt.event.MouseAdapter() {
                public void mouseClicked(java.awt.event.MouseEvent evt) {
                    textBodyDoubleClick(evt);
                }
            });
        }
        this.setDoubleBuffered(true);
    }
    protected void textBodyDoubleClick(MouseEvent evt) {
        if (evt.getClickCount() == 2){
            String partner_id = (messageObject.id1.equals(messageObject.id2)) ? messageObject.id1 : (messageObject.id1.equals(AFriendClient.user.id)) ? messageObject.id2 : messageObject.id1;
            try{
                JFileChooser fileChooser = new JFileChooser();
                // fileChooser will be used to save the file
                // set name of the file to be saved to textBody.text
                fileChooser.setSelectedFile(new File(textBody.getText()));
                int result = fileChooser.showSaveDialog(this);
                if (result == JFileChooser.APPROVE_OPTION){
                    File file = fileChooser.getSelectedFile();
                    String fileName = file.getName();
                    String filePath = file.getAbsolutePath();
                    authorBody.setText("Try again later!");
                    authorBody.setForeground(Color.red);
                    // check if file exists
                    if (file.exists()){
                        int response = JOptionPane.showConfirmDialog(this, "File already exists. Overwrite?", "Overwrite?", JOptionPane.YES_NO_OPTION);
                        if (response == JOptionPane.NO_OPTION){
                            return;
                        }
                    }
                    try{
                        // delete file if it exists
                        if (file.exists()){
                            file.delete();
                        }
                    }
                    catch(Exception e){
                        e.printStackTrace();
                        // show error message
                        JOptionPane.showMessageDialog(this, "Error overwriting file", "Error", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                    AFriendClient.queueCommand(Tools.combine(("1905" + partner_id).getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(this.messageObject.messagenumber+"").getBytes(StandardCharsets.US_ASCII)));
                    AFriendClient.files.put(messageObject.id1 + "_" + messageObject.id2 + "_" + messageObject.messagenumber + ".", new AFile(filePath, 0));
                }
            }
            catch(Exception e){
                e.printStackTrace();
            }
        }
    }
    public AFChatItem(String text){
        this(text, false);
    }
    public AFChatItem(String text, boolean isMine) {
        this.text = text;
        this.isMine = isMine;

        initComponents();
        
    }

    String datetimeNow = new Timestamp(System.currentTimeMillis()).toString();

    private void initComponents() {
        authorBody = new JTextArea();
        authorBody.setLineWrap(true);
        authorBody.setWrapStyleWord(true);
        authorBody.setEditable(false);
        authorBody.setFont(new Font("Arial", Font.PLAIN, 12));
        authorBody.setMargin(new Insets(0, 0, 0, 0));
        authorBody.setOpaque(false);
        //authorBody.setBackground(Color.PINK);

        topPanel = new JPanel();
        //topPanel.setBackground(Color.blue);
        topPanel.setOpaque(false);
        topPanel.setBorder(null);
        if (isMine) {
            topPanel.setLayout(new FlowLayout(FlowLayout.TRAILING));
            authorBody.setComponentOrientation(java.awt.ComponentOrientation.RIGHT_TO_LEFT);
        }
        else {
            topPanel.setLayout(new FlowLayout(FlowLayout.LEADING));
        }
        topPanel.add(authorBody);

        if (this.messageObject != null && (this.messageObject.type == 0 || this.messageObject.type == 3)){
            textBody = new javax.swing.JTextArea();
            textBody.setOpaque(false);
            textBody.setBackground(new Color(0, 0, 0, 0));
            textBody.setLineWrap(true);
            textBody.setWrapStyleWord(true);
            textBody.setFont(Font.decode("Arial-14"));
            textBody.setMargin(new Insets(5, 5, 5, 5));
            textBody.setBorder(null);
            textBody.setText(this.messageObject.message);
            
        
            // make textBody readonly but display cursor when mouse hover
            // start copilot code
            textBody.setEditable(false);
            textBody.setFocusable(true);
            textBody.setCursor(new java.awt.Cursor(java.awt.Cursor.TEXT_CURSOR));
            textBody.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mouseEntered(java.awt.event.MouseEvent evt) {
                    textBody.setCursor(new java.awt.Cursor(java.awt.Cursor.TEXT_CURSOR));
                    buttonDelete.setVisible(true);
                }
                @Override
                public void mouseExited(java.awt.event.MouseEvent evt) {
                    textBody.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
                    buttonDelete.setVisible(false);
                }
            });
            // end copilot code

            scroll = new JScrollPane(textBody);
            scroll.setBorder(null);
            scroll.setOpaque(false);
            scroll.setBackground(new Color(0, 0, 0, 0));
            scroll.getViewport().setOpaque(false);
            scroll.getViewport().setBackground(new Color(0, 0, 0, 0));
            scroll.removeMouseWheelListener(scroll.getMouseWheelListeners()[0]);

            panelBody = new MessagePanel();
            panelBody.setBorder(new EmptyBorder(new Insets(5, 5, 5, 5)));
            panelBody.setLayout(new java.awt.FlowLayout());
            panelBody.add(scroll);
        }
        else if (this.messageObject != null && this.messageObject.type == 1){
            image = Tools.BASE64ToImage(this.messageObject.message);
            panelBody = new MessagePanel(){
                @Override
                public void paintComponent(Graphics g) {
                    super.paintComponent(g);
                    Graphics2D g2d = (Graphics2D) g.create();
                    g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                    g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
                    g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
                    g2d.drawImage(image, 0, 0, panelBody.getWidth(), panelBody.getHeight(), panelBody);
                }
            };
            // click event
            panelBody.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2) {
                        if (image != null) {
                            try{
                                File file = File.createTempFile(UUID.randomUUID().toString(), ".png");
                                ImageIO.write(image, "png", file);
                                java.awt.Desktop.getDesktop().open(file);
                            } 
                            catch(Exception ee){
                                ee.printStackTrace();
                                
                                JFrame frame = new JFrame();
                                frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                                frame.setBounds(100, 100, image.getWidth(), image.getHeight());
                                frame.setLayout(new FlowLayout());
                                JLabel label = new JLabel(new ImageIcon(image));
                                frame.add(label);
                                frame.setVisible(true);
                            }
                        }
                    }
                }
            });
        }
        else{
            textBody = new javax.swing.JTextArea();
            textBody.setOpaque(false);
            textBody.setBackground(new Color(0, 0, 0, 0));
            //textBody.setForeground(new Color(255, 0, 0, 255));
            textBody.setLineWrap(true);
            textBody.setWrapStyleWord(true);
            textBody.setFont(Font.decode("Arial-14"));
            textBody.setMargin(new Insets(5, 5, 5, 5));
            textBody.setBorder(null);
            textBody.setText(this.text);
        
            // make textBody readonly but display cursor when mouse hover
            // start copilot code
            textBody.setEditable(false);
            textBody.setFocusable(true);
            textBody.setCursor(new java.awt.Cursor(java.awt.Cursor.TEXT_CURSOR));
            textBody.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mouseEntered(java.awt.event.MouseEvent evt) {
                    textBody.setCursor(new java.awt.Cursor(java.awt.Cursor.TEXT_CURSOR));
                    buttonDelete.setVisible(true);
                }
                @Override
                public void mouseExited(java.awt.event.MouseEvent evt) {
                    textBody.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
                    buttonDelete.setVisible(false);
                }
            });
            // end copilot code

            scroll = new JScrollPane(textBody);
            scroll.setBorder(null);
            scroll.setOpaque(false);
            scroll.setBackground(new Color(0, 0, 0, 0));
            scroll.getViewport().setOpaque(false);
            scroll.getViewport().setBackground(new Color(0, 0, 0, 0));
            scroll.removeMouseWheelListener(scroll.getMouseWheelListeners()[0]);

            panelBody = new MessagePanel();
            panelBody.setBorder(new EmptyBorder(new Insets(5, 5, 5, 5)));
            panelBody.setLayout(new java.awt.FlowLayout());
            panelBody.add(scroll);
        }
        //panelBody.setAlignmentX(0f);

        buttonDelete = new javax.swing.JButton();
        buttonDelete.setBorder(null);
        buttonDelete.setContentAreaFilled(false);
        buttonDelete.setBorderPainted(false);
        buttonDelete.setPreferredSize(new Dimension(DELETEICON_WIDTH, DELETEICON_HEIGHT));
        buttonDelete.setMaximumSize(new Dimension(DELETEICON_WIDTH, DELETEICON_HEIGHT));
        buttonDelete.setMinimumSize(new Dimension(DELETEICON_WIDTH, DELETEICON_HEIGHT));
        buttonDelete.setVisible(false);
        buttonDelete.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                chatItemMouseEntered(evt);
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent evt) {
                chatItemMouseExited(evt);
            }
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                buttonDeleteMouseClicked(evt);
            }
        });


        bottomPanel = new javax.swing.JPanel();
        bottomPanel.setBorder(null);
        bottomPanel.setOpaque(false);
        bottomPanel.setBackground(Color.YELLOW);

        try{
            //Resize the image to fit the button
            Image newImg = new ImageIcon(deleteIcon.getScaledInstance(DELETEICON_WIDTH, DELETEICON_HEIGHT, Image.SCALE_SMOOTH)).getImage();
            buttonDelete.setIcon(new ImageIcon(newImg));
        }
        catch(Exception e){
            System.out.println("Error: " + e.getMessage());
        }


        if (isMine) {
            //this.setLayout(new FlowLayout(FlowLayout.TRAILING));
            bottomPanel.setLayout(new FlowLayout(FlowLayout.TRAILING));
            bottomPanel.add(buttonDelete);
            bottomPanel.add(panelBody);
        }
        else {
            //this.setLayout(new java.awt.FlowLayout(FlowLayout.LEADING));
            bottomPanel.setLayout(new FlowLayout(FlowLayout.LEADING));
            bottomPanel.add(panelBody);
            bottomPanel.add(buttonDelete);
        }

        this.setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        this.add(topPanel);
        this.add(bottomPanel);
        this.setOpaque(false);
        //this.add(panelBody);
        //this.setBackground(Color.RED);

        this.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent evt) {
                chatItemComponentResized(evt);
            }
        });

        // mouse hover event
        this.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                chatItemMouseEntered(evt);
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent evt) {
                chatItemMouseExited(evt);
            }
        });
    }

    protected void buttonDeleteMouseClicked(MouseEvent evt) {
        // display dialog
        int result = JOptionPane.showConfirmDialog(this, "Are you sure you want to delete this message?", "Delete Message", JOptionPane.YES_NO_OPTION);
        if (result == JOptionPane.YES_OPTION) {
            // delete message
            /* 
            this.setVisible(false);
            this.removeAll();
            this.revalidate();
            this.repaint();
            */
            ((PanelChat)this.getParent().getParent().getParent().getParent().getParent()).removeMessage(this.getId());
        }
    }

    public long getId(){
        return this.messageObject.messagenumber;
    }

    public void updateDateTime(){
        if (isMine){
            java.time.ZonedDateTime today = java.time.ZonedDateTime.now();
            // set today to 0 hours 0 minutes 0 seconds
            today = today.withHour(0).withMinute(0).withSecond(0).withNano(0);
            Instant instant = Instant.ofEpochMilli(this.messageObject.timesent.getTime());
            LocalDateTime datetime = LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
            if (this.messageObject.timesent.before(new Timestamp(today.toEpochSecond()*1000))){
                authorBody.setText(datetime.format(DateTimeFormatter.ofPattern("dd/MM/yyyy\nHH:mm")));
                //System.out.println("1");
            }
            else {
                authorBody.setText(datetime.format(DateTimeFormatter.ofPattern("HH:mm")));
                //System.out.println(2);
            }
        }
        else if (this.getParent().getParent().getParent().getParent().getParent() instanceof PanelChat){
            PanelChat parent = (PanelChat)this.getParent().getParent().getParent().getParent().getParent();
            String author = parent.account.name;
            java.time.ZonedDateTime today = java.time.ZonedDateTime.now();
            // set today to 0 hours 0 minutes 0 seconds
            today = today.withHour(0).withMinute(0).withSecond(0).withNano(0);
            Instant instant = Instant.ofEpochMilli(this.messageObject.timesent.getTime());
            LocalDateTime datetime = LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
            if (this.messageObject.timesent.before(new Timestamp(today.toEpochSecond()*1000))){
                authorBody.setText(author + "\n" + datetime.format(DateTimeFormatter.ofPattern("dd/MM/yyyy\nHH:mm")));
                //System.out.println(3);
            }
            else {
                authorBody.setText(author + "\n" + datetime.format(DateTimeFormatter.ofPattern("HH:mm")));
                //System.out.println(4);
            }
        }
        timetext = authorBody.getText();
        //System.out.println(timetext);
    }

    protected void chatItemMouseExited(MouseEvent evt) {
        // make buttonDelete invisible
        buttonDelete.setVisible(false);
    }

    protected void chatItemMouseEntered(MouseEvent evt) {
        // make buttonDelete visible
        buttonDelete.setVisible(true);
    }

    protected void chatItemComponentResized(ComponentEvent evt) {
        int width = this.getParent().getWidth()*3/5-20;
          
        if (authorBody != null){
            Graphics ga = authorBody.getGraphics();
            if (ga == null) return;
            int authorHeight = authorBody.getPreferredSize().height;
            int authorWidth = ga.getFontMetrics(authorBody.getFont()).stringWidth(authorBody.getText());
            int newAuthorWidth = (authorWidth < width)? authorWidth : width ;
            authorBody.setSize(new java.awt.Dimension(newAuthorWidth , authorHeight));
            topPanel.setSize(new java.awt.Dimension(this.getSize().width, authorHeight + 10));
        }
        
        if (messageObject != null && (messageObject.type == 0 || messageObject.type == 3)) {
            int height = textBody.getPreferredSize().height; 
            Graphics g = textBody.getGraphics();
            int textWidth = g.getFontMetrics(textBody.getFont()).stringWidth(textBody.getText());
            //textBody.setSize(new java.awt.Dimension(this.getPreferredSize().width -20, textBody.getPreferredSize().height)); the original code
            int newWidth = (textWidth + 20 < width)? textWidth : width - 20;
            textBody.setSize(new java.awt.Dimension(newWidth + 10, height));
            panelBody.setSize(new java.awt.Dimension(newWidth + 30, height + 20));
            //panelBody.setPreferredSize(new java.awt.Dimension(newWidth + 30, height + 20));
        }
        else if (messageObject != null && messageObject.type == 1) {
            if (image.getWidth() > width){
                panelBody.setSize(new Dimension(width, width * image.getHeight()/image.getWidth()));
                panelBody.setPreferredSize(new Dimension(width, width * image.getHeight()/image.getWidth()));
            }
            else{
                panelBody.setSize(new Dimension(image.getWidth(), image.getHeight()));
                panelBody.setPreferredSize(new Dimension(image.getWidth(), image.getHeight()));
            }
        }
        else{
            int height = textBody.getPreferredSize().height; 
            if (maxMessageWidth == -1){
                Graphics g = textBody.getGraphics();
                String[] lines = text.split("\n");
                int maxLineWidth = 0;
                for (String line : lines) {
                    int lineWidth = g.getFontMetrics().stringWidth(line);
                    if (lineWidth > maxLineWidth) {
                        maxLineWidth = lineWidth;
                    }
                }
                maxMessageWidth = maxLineWidth;
            }
            int textWidth = maxMessageWidth;
            int newWidth = (textWidth + 20 < width)? textWidth : width - 20;
            textBody.setSize(new java.awt.Dimension(newWidth + 10, height));
            panelBody.setSize(new java.awt.Dimension(newWidth + 30, height + 20));
        }
        
    }

    @Override
    public java.awt.Dimension getMinimumSize(){
        return getPreferredSize();
    }

    @Override
    public java.awt.Dimension getMaximumSize(){
        return getPreferredSize();
    }

    @Override
    public java.awt.Dimension getPreferredSize(){
        return new java.awt.Dimension(this.getParent().getWidth()*3/5 + (buttonDelete.isVisible()? DELETEICON_WIDTH : 0), panelBody.getPreferredSize().height + panelBody.getInsets().top + panelBody.getInsets().bottom + (showDetail? topPanel.getSize().height : 0));
    }

    private String text;
    public boolean isMine;
    public JTextArea textBody;
    private JScrollPane scroll;
    private MessagePanel panelBody;
    private JPanel bottomPanel;
    private JButton buttonDelete;
    private JPanel topPanel;
    private JTextArea authorBody;
}
