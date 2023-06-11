package ui.customcomponents;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Image;
import java.awt.event.ComponentEvent;
import java.awt.event.KeyEvent;
import java.awt.FlowLayout;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.awt.image.BufferedImageOp;
import java.io.File;
import java.awt.AlphaComposite;

import javax.imageio.ImageIO;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.Clip;
import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.ActionMap;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.InputMap;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.UIManager;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.plaf.basic.BasicScrollBarUI;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import com.mycompany.afriendjava.AFriendClient;
import com.mycompany.afriendjava.Account;
import com.mycompany.afriendjava.MainUI;
import com.mycompany.afriendjava.MessageObject;
import com.mycompany.afriendjava.Program;
import com.mycompany.afriendjava.Tools;
import com.mycompany.afriendjava.Utils;

import custom.CircleAvatar;

public class PanelChat extends javax.swing.JPanel{

    private JPanel panelTop;
    private CircleAvatar friendPicture;
    public JLabel labelFriendName;
    private JLabel labelState;
    private JButton buttonDelete;


    public JPanel panelChat;
    private JScrollPane panelChatScroll;

    private JPanel panelBottom;
    private JTextArea textboxWriting;
    JScrollPane textboxScroll;
    private JButton buttonSend;
    private JButton sendImageButton;
    private JButton sendFileButton;
    
    private java.util.Timer timerChat;

    public Account account;
    public String id;
    private long loadedmessagenumber = 0;
    private byte state;
    private Color stateColor = Color.decode("#DCDCDC");
    private java.awt.BasicStroke stroke1 = new java.awt.BasicStroke(1f);

    public ConcurrentLinkedQueue<String> filesToSend = new ConcurrentLinkedQueue<String>();
    public HashMap<Long, AFChatItem> messages = new HashMap<Long, AFChatItem>();
    public Image avatar =  (new ImageIcon(getClass().getResource("newUser.png"))).getImage();
    public Image deleteIcon = (new ImageIcon(getClass().getResource("deleteIcon.png"))).getImage();
    public Image sendIcon = (new ImageIcon(getClass().getResource("paper-plane-regular.png"))).getImage();
    public Image sendImageIcon = (new ImageIcon(getClass().getResource("camera-outline.png"))).getImage();
    public Image sendFileIcon = (new ImageIcon(getClass().getResource("file_icon_207228.png"))).getImage();

    public int isFormShowing;
    public boolean isShowing;
    public boolean isLoadingOldMessages = false;
    private int current_vertical_value = 0;
    
    public long currentmin = -1;
    public long currentmax = -1;

    private static final String TEXT_SUBMIT = "text-submit";

    protected int timi = 240; // this is the elapsed time (in second) between 2 message needed to show timer

    private void initializeComponent(){
        
        friendPicture = new CircleAvatar();
        labelFriendName = new JLabel();
        labelState = new JLabel();
        buttonDelete = new JButton();
        panelChat = new JPanel(){
            @Override
            public void paintComponent(Graphics g){
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2d.setColor(Color.GRAY);
                g2d.setStroke(stroke1);
                g2d.drawLine(0, 0, 0, panelChat.getSize().height);
            }
        };
        panelBottom = new JPanel(){
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
                return new java.awt.Dimension(this.getParent().getSize().width, 144);
            }

            @Override
            public void paintComponent(Graphics g){
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2d.setColor(Color.GRAY);
                g2d.setStroke(stroke1);
                g2d.drawLine(0, 1, panelBottom.getSize().width, 1);
                g2d.drawLine(0, 0, 0, panelBottom.getSize().height);
            }
        };

        friendPicture.setBounds(18, 7, 45, 45);
        this.friendPicture.setImage(new ImageIcon(this.avatar.getScaledInstance(friendPicture.getWidth(), friendPicture.getHeight(), Image.SCALE_SMOOTH)));
        this.friendPicture.repaint();

        labelFriendName.setBounds(72, 10, 80, 18);
        labelFriendName.setFont(new java.awt.Font("Arial", 0, 12));
        labelFriendName.setText("ADSADSADSADSADDASDDASDSAASDASDASDASADSADSADSASSD ASD ADSASD ASD ASD DS ASD ADS ASD AD SASD ASD AD SASD ");

        labelState.setBounds(73, 32, 49, 18);
        labelState.setFont(new java.awt.Font("Arial", 0, 12));
        labelState.setText("offline");

        buttonDelete.setOpaque(false);
        buttonDelete.setBackground(new Color(230, 244, 241));
        buttonDelete.setBounds(860, 10, 40, 40);
        try{
            //Resize the image to fit the button
            Image newImg = new ImageIcon(deleteIcon.getScaledInstance(buttonDelete.getSize().width - 6, buttonDelete.getSize().height - 6, Image.SCALE_SMOOTH)).getImage();
            buttonDelete.setIcon(new ImageIcon(newImg));
        }
        catch(Exception e){
            System.out.println("Error: " + e.getMessage());
        }
        buttonDelete.addActionListener(new ActionListener(){
            @Override
            public void actionPerformed(ActionEvent e){
                // yes no dialog
                int n = JOptionPane.showConfirmDialog(null, "Are you sure you want to delete this conversation?", "Delete Conversation", JOptionPane.YES_NO_OPTION);
                if(n == 0){
                    // yes no dialog
                    int n2 = JOptionPane.showConfirmDialog(null, "This action will DELETE ALL YOUR MESSAGES with THIS PERSON! Think twice! Are you serious?", "Delete Conversation", JOptionPane.YES_NO_OPTION);
                    if (n2 == 0){
                        AFriendClient.queueCommand(("5859" + id).getBytes(StandardCharsets.UTF_16LE));
                        
                    }
                }
            }
        });


        panelTop = new JPanel(){
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
                return new java.awt.Dimension(this.getParent().getSize().width, 60);
            }

            @Override
            protected void paintComponent(Graphics g){
                super.paintComponent(g);
                // graphics2D object
                Graphics2D g2d = (Graphics2D) g;
                //set thickness of the stroke
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2d.setStroke(stroke1);
                //g2d.setColor(stateColor);
                //g2d.drawOval(friendPicture.getLocation().x - 1, friendPicture.getLocation().y - 1, friendPicture.getWidth() + 1, friendPicture.getHeight() + 1);
                g2d.setColor(Color.gray);
                g2d.drawLine(0, panelTop.getSize().height - 1, panelTop.getSize().width, panelTop.getSize().height - 1);
                g2d.drawLine(0, panelTop.getSize().height, 0, 0);
            }
        };

        panelTop.setLayout(null);
        panelTop.setOpaque(false);
        //panelTop.setBackground(new Color(46, 140, 130, 150));
        panelTop.add(friendPicture);
        panelTop.add(labelFriendName);
        panelTop.add(labelState);
        panelTop.add(buttonDelete);
        panelTop.addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentResized(java.awt.event.ComponentEvent evt) {
                panelTopComponentResized(evt);
            }
        });

        panelChat.setLayout(new BoxLayout(panelChat, BoxLayout.Y_AXIS));
        panelChat.setOpaque(false);

        panelChatScroll = new JScrollPane(panelChat);
        panelChatScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        panelChatScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        panelChatScroll.setOpaque(false);
        panelChatScroll.setBorder(null);
        panelChatScroll.setBounds(0, 0, 912, 474);
        panelChatScroll.getVerticalScrollBar().setUnitIncrement(30);
        panelChatScroll.getVerticalScrollBar().setBlockIncrement(30);
        panelChatScroll.setWheelScrollingEnabled(true);
        panelChatScroll.getViewport().setOpaque(false);

        panelChat.add(Box.createVerticalGlue());

        
        textboxWriting = new JTextArea();
        textboxWriting.setBorder(null);
        textboxWriting.setOpaque(false);
        textboxWriting.setLineWrap(true);
        textboxWriting.setWrapStyleWord(true);
        textboxWriting.setFont(new java.awt.Font("Arial", 0, 12));
        textboxWriting.setBounds(0, 0, 912, 120);
        InputMap input = textboxWriting.getInputMap();
        KeyStroke enter = KeyStroke.getKeyStroke("ENTER");
        KeyStroke shiftEnter = KeyStroke.getKeyStroke("shift ENTER");
        input.put(shiftEnter, "insert-break");  // input.get(enter)) = "insert-break"
        input.put(enter, TEXT_SUBMIT);
        Action action = textboxWriting.getActionMap().get("paste-from-clipboard");
        textboxWriting.getActionMap().put("paste-from-clipboard", new PasteAction(action, id));


        ActionMap actions = textboxWriting.getActionMap();
        actions.put(TEXT_SUBMIT, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                submitText();
            }
        });
        // make textboxWriting scrollable
        textboxScroll = new JScrollPane(textboxWriting);
        textboxScroll.setOpaque(false);
        textboxScroll.setBorder(null);
        textboxScroll.setBounds(0, 0, 912, 120);
        textboxScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        textboxScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        textboxScroll.setWheelScrollingEnabled(true);
        textboxScroll.getViewport().setOpaque(false);

        buttonSend = new JButton();
        buttonSend.setOpaque(false);
        buttonSend.setBackground(new Color(230, 244, 241));
        buttonSend.setBounds(872, 126, 40, 20);
        try{
            //Resize the image to fit the button
            Image newImg = new ImageIcon(sendIcon.getScaledInstance(buttonSend.getSize().width - 8, buttonSend.getSize().height - 4, Image.SCALE_SMOOTH)).getImage();
            buttonSend.setIcon(new ImageIcon(newImg));
        }
        catch(Exception e){
            System.out.println("Error: " + e.getMessage());
        }
        // click on buttonSend to submit text
        buttonSend.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                submitText();
            }
        });

        sendImageButton = new JButton();
        sendImageButton.setOpaque(false);
        sendImageButton.setBackground(new Color(230, 244, 241));
        sendImageButton.setBounds(1, 126, 20, 20);
        try{
            //Resize the image to fit the button
            Image newImg = new ImageIcon(sendImageIcon.getScaledInstance(sendImageButton.getSize().width - 2, sendImageButton.getSize().height - 2, Image.SCALE_SMOOTH)).getImage();
            sendImageButton.setIcon(new ImageIcon(newImg));
        }
        catch(Exception e){
            System.out.println("Error: " + e.getMessage());
        }
        // add click action to sendImageButton
        sendImageButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // create new function
                sendImage();
            }
        });

        sendFileButton = new JButton();
        sendFileButton.setOpaque(false);
        sendFileButton.setBackground(new Color(230, 244, 241));
        sendFileButton.setBounds(21, 126, 20, 20);
        try{
            //Resize the image to fit the button
            Image newImg = new ImageIcon(sendFileIcon.getScaledInstance(sendFileButton.getSize().width - 2, sendFileButton.getSize().height - 2, Image.SCALE_SMOOTH)).getImage();
            sendFileButton.setIcon(new ImageIcon(newImg));
        }
        catch(Exception e){
            System.out.println("Error: " + e.getMessage());
        }
        // add click action to sendFileButton
        sendFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // create new function
                sendFile();
            }
        });

        panelBottom.setLayout(null);
        panelBottom.setOpaque(false);
        panelBottom.add(textboxScroll);
        panelBottom.add(buttonSend);
        panelBottom.add(sendImageButton);
        panelBottom.add(sendFileButton);
        panelBottom.addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentResized(java.awt.event.ComponentEvent evt) {
                panelBottomComponentResized(evt);
            }
        });

        this.setLayout(null);
        this.setOpaque(false);
        this.setBackground(Color.WHITE);

        this.setSize(new Dimension(912, 681));
        this.add(panelTop);
        this.add(panelChatScroll);
        this.add(panelBottom);
        // resize event
        this.addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentResized(java.awt.event.ComponentEvent evt) {
                panelChat_Resize(evt);
            }
        });
        // load event
        this.addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentShown(java.awt.event.ComponentEvent evt) {
                panelChat_Load(evt);
            }
        });
    }

    protected void sendFile() {
        try{
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
            /* 
            // set all file types
            FileNameExtensionFilter filter = new FileNameExtensionFilter("All Files", "*.*");
            fileChooser.setFileFilter(filter);
            */
            // multiple files
            fileChooser.setMultiSelectionEnabled(true);
            int result = fileChooser.showDialog(this, "Send Files");
            if (result == JFileChooser.APPROVE_OPTION) {
                File[] files = fileChooser.getSelectedFiles();
                for(File file : files){
                    try{
                        String fileName = file.getName();
                        String fileSize = String.valueOf(file.length());
                        AFriendClient.queueCommand(
                            Tools.combine(
                                ("1903" + id + Tools.data_with_unicode_byte(fileName)).getBytes(StandardCharsets.UTF_16LE),
                                (Tools.data_with_ASCII_byte(fileSize)).getBytes(StandardCharsets.US_ASCII)
                            )
                        );
                        filesToSend.add(file.getAbsolutePath());
                    }
                    catch (Exception e){
                        e.printStackTrace();
                    }
                }
            }
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }

    protected void sendImage() {
        try{
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
            // all image files types
            FileNameExtensionFilter filter = new FileNameExtensionFilter("Image files", ImageIO.getReaderFileSuffixes());
            fileChooser.addChoosableFileFilter(filter);
            // can select multipe files at once
            fileChooser.setMultiSelectionEnabled(true);
            int result = fileChooser.showDialog(this, "Send Images");
            if (result == JFileChooser.APPROVE_OPTION) {
                File[] files = fileChooser.getSelectedFiles();
                for (File file : files) {
                    try{
                        // creare BufferedImage from file
                        BufferedImage image = ImageIO.read(file);
                        String base64Image = Tools.ImageToBASE64(image);
                        // send image to server
                        AFriendClient.queueCommand(Tools.combine(("1902"+id).getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(base64Image).getBytes(StandardCharsets.US_ASCII)));
                    }
                    catch(Exception e){
                        e.printStackTrace();
                    }
                }
            }
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }

    protected void panelChat_Load(ComponentEvent evt) {
        // focus on textboxWriting
        textboxWriting.requestFocus();

    }

    protected void submitText() {
        try{
            String text = textboxWriting.getText();
            if(text != null && !text.isBlank()){
                String messageText = textboxWriting.getText().trim();
                textboxWriting.setText("");
                textboxWriting.requestFocus();
                AFriendClient.sendToId(id, AFriendClient.user.id, messageText);
            }
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }

    protected void panelBottomComponentResized(ComponentEvent evt) {
        textboxScroll.setBounds(0, 0, panelBottom.getSize().width, panelBottom.getSize().height - 22);
        buttonSend.setBounds(panelBottom.getSize().width - 40, panelBottom.getSize().height + 2 - 20, 40, 20);
    }

    protected void panelTopComponentResized(ComponentEvent evt) {
        buttonDelete.setLocation(panelTop.getSize().width - 52, 10);
        labelFriendName.setSize(buttonDelete.getLocation().x - labelFriendName.getLocation().x - 50, 18);
    }

    private void panelChat_Resize(java.awt.event.ComponentEvent evt) {
        int width = this.getParent().getSize().width;
        int height = this.getParent().getSize().height;

        this.setSize(width, height);
        currentBackgroundImage = new ImageIcon(avatar.getScaledInstance(width, height, Image.SCALE_SMOOTH)).getImage();
        currentBufferedImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        this.panelTop.setBounds(0, 0, width, 60);
        this.panelChatScroll.setBounds(0, 60, width, height - 60 - 144);
        this.panelBottom.setBounds(0, height - 144, width, 144);
        //System.out.println(panelChat.getSize().width + " " + panelChat.getSize().height);
        //System.out.println(panelChatScroll.getSize().width + " " + panelChatScroll.getSize().height);
    }

    Image currentBackgroundImage = null;
    BufferedImage currentBufferedImage = null;
    private AFChatItem currentChatItem;
    private boolean currentChatItemShowing;

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        if (currentBackgroundImage == null || currentBufferedImage == null) {
            return;
        }
        Graphics2D g2d = currentBufferedImage.createGraphics();
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2d.setColor(Color.WHITE);
        g2d.fillRect(0, 0, this.getSize().width, this.getSize().height);
        g2d.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.19f));
        g2d.drawImage(currentBackgroundImage, 0, 0, this.getSize().width, this.getSize().height, this);
        g2d.dispose();
        // set the background to the buffered image
        g.drawImage(currentBufferedImage, 0, 0, this);
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
        return new java.awt.Dimension(this.getParent().getSize().width, this.getParent().getSize().height);
    }

    private void mustInit(){
        initializeComponent();
        this.setDoubleBuffered(true);
    }
    public PanelChat(){
        mustInit();
    }

    public byte type;

    public PanelChat(Account acc) {
        this.account = acc;
        this.id = account.id;
        this.type = account.type;
        mustInit();
        this.isFormShowing = 0;
        this.isShowing = false;

        this.setName("panelChat_" + account.id);
        labelFriendName.setText(account.name);
        this.setState(account.state);
        // this click listener
        this.addMouseListener(new java.awt.event.MouseAdapter(){
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e){
                if(e.getButton() == java.awt.event.MouseEvent.BUTTON1){
                    // focus on textboxWriting
                    textboxWriting.requestFocus();
                }
            }
        });
    }

    public byte getState(){
        return this.state;
    }

    public void setState(byte state){
        if (this.state != state){
            this.state = state;
            if (state == 0){
                stateColor = Color.decode("#DCDCDC");
                labelState.setText("offline");
                labelState.setForeground(stateColor);
                friendPicture.setBorderColor(stateColor);
                friendPicture.revalidate();
                friendPicture.repaint();
                //panelTop.revalidate();
                //panelTop.repaint();
            }
            else if (state == 1){
                stateColor = Color.decode("#00FF7F");
                labelState.setText("online");
                labelState.setForeground(stateColor);
                friendPicture.setBorderColor(stateColor);
                friendPicture.revalidate();
                friendPicture.repaint();
                //panelTop.revalidate();
                //panelTop.repaint();
            }
            else {
                stateColor = Color.decode("#FF0000");
                labelState.setText("away");
                labelState.setForeground(stateColor);
                friendPicture.setBorderColor(stateColor);
                friendPicture.revalidate();
                friendPicture.repaint();
                //panelTop.revalidate();
                //panelTop.repaint();
            }
            //this.revalidate();
            //this.repaint();
        }
    }

    public AFChatItem getCurrentChatItem(){
        return this.currentChatItem;
    }

    public void setCurrentChatItem(AFChatItem chatItem){
        if (currentChatItem == chatItem){
            return;
        }
        System.out.println("set");
        if (currentChatItem != null){
            currentChatItem.setShowDetail(currentChatItemShowing);
        }
        currentChatItem = chatItem;
        currentChatItemShowing = !chatItem.getShowDetail();
    }

    public Timestamp DateTimeOfLastMessage(){
        if (messages.size() == 0){
            System.out.println(new Timestamp(System.currentTimeMillis()));
            return new Timestamp(System.currentTimeMillis());
        }
        else {
            System.out.println("MO " + messages.get(currentmax).messageObject.timesent);
            return messages.get(currentmax).messageObject.timesent;
        }
    }

    public void removeMessage(Long messageNumber) {
        byte type = messages.get(messageNumber).messageObject.type;
        panelChat.remove(messages.get(messageNumber).getParent());
        messages.remove(messageNumber);
        Program.mainform.contactItems.get(id).setLastMessage(this.getLastMessage());
        if (messages.size() > 0){
            // scroll to the last message
            panelChatScroll.getVerticalScrollBar().setValue(panelChatScroll.getVerticalScrollBar().getMaximum());
        }

        // code to remove message
        String id1 = AFriendClient.user.id;
        String id2 = id;
        if (type == 3) {
            // set filesOnCancel id1+"_"+id2+"_"+messageNumber to true
            String fileId = id1 + "_" + id2 + "_" + messageNumber;
            AFriendClient.filesOnCancel.put(fileId, true);
        }
        AFriendClient.queueCommand(("2002"+this.id+Tools.data_with_unicode_byte(messageNumber.toString())).getBytes(StandardCharsets.UTF_16LE));
    }

    public String getFirstMessage(){
        if (messages.size() == 0){
            return "";
        }
        evaluateMaxmin();
        return messages.get(currentmin).messageObject.message;
    }

    public String getLastMessage() {
        if (messages.size() == 0){
            System.out.println("New conversation!");
            return "New conversation!";
        }
        this.evaluateMaxmin();
        MessageObject messageObject = messages.get(currentmax).messageObject;
        if (messageObject.type == 0){
            System.out.println(messageObject.message);
            return messageObject.message;
        }
        else if (messageObject.type == 1){
            System.out.println("Image");
            return "<Photo>";
        }
        System.out.println("null");
        return "";
    }

    private void evaluateMaxmin() {
        if (messages.size() == 0) return;
        while (!messages.containsKey(currentmax)) currentmax -= 1;
        while (!messages.containsKey(currentmin)) currentmin += 1;
        System.out.println(currentmax + " " + currentmin);
    }

    public boolean isLastMessageFromYou() {
        if (panelChat.getComponentCount() == 1){
            return true;
        }
        evaluateMaxmin();
        AFChatItem message = messages.get(currentmax);
        if (message.isMine){
            return true;
        }
        return false;
    }

    public void addMessage(MessageObject message) {
        try{
            if (messages.containsKey(message.messagenumber)){
                System.out.println("Message already exists");
                return;
            }
            if (currentmin == -1 || currentmin > message.messagenumber) currentmin = message.messagenumber;
            if (currentmax == -1 || currentmax < message.messagenumber) currentmax = message.messagenumber;
            this.loadedmessagenumber = message.messagenumber;
            AFChatItem chatItem = new AFChatItem(message);
            messages.put(message.messagenumber, chatItem);
            panelChat.add(ChatLayout.createChatItemBox(chatItem));
            chatItem.setShowDetail(false);
            if (message.type == 3 || !messages.containsKey(message.messagenumber - 1) || messages.get(message.messagenumber - 1).messageObject.type == 3 || (message.timesent.getTime()/1000 - messages.get(message.messagenumber - 1).messageObject.timesent.getTime()/1000) > timi)
            {
                chatItem.setShowDetail(true);
            }
            chatItem.updateDateTime();
            if (isFormShowing == 1 && panelChatScroll.getVerticalScrollBar().getValue() > panelChatScroll.getVerticalScrollBar().getMaximum() - 350 - chatItem.getSize().height)
            {
                panelChatScroll.getVerticalScrollBar().setValue(panelChatScroll.getVerticalScrollBar().getMaximum());
            }
            else if (isFormShowing == 0 && panelChatScroll.getVerticalScrollBar().getValue() > panelChatScroll.getVerticalScrollBar().getMaximum() - 2 * panelChat.getSize().height - chatItem.getSize().height )
            {
                panelChatScroll.getVerticalScrollBar().setValue(panelChatScroll.getVerticalScrollBar().getMaximum());
            }
            else if (chatItem.isMine){
                panelChatScroll.getVerticalScrollBar().setValue(panelChatScroll.getVerticalScrollBar().getMaximum());
            }
            if (!chatItem.isMine && isFormShowing > 0){
                // flash form
                Utils.AlertOnWindow(MainUI.subForms.get(id));
                // play message sound
                try {
                    javax.sound.sampled.Clip clip = javax.sound.sampled.AudioSystem.getClip();
                    clip.open(javax.sound.sampled.AudioSystem.getAudioInputStream(new java.io.File(PanelChat.class.getResource("ring tone - Kalimbist.wav").toURI().getPath())));
                    clip.start();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            else if (!chatItem.isMine){
                // play message sound
                try {
                    javax.sound.sampled.Clip clip = javax.sound.sampled.AudioSystem.getClip();
                    clip.open(javax.sound.sampled.AudioSystem.getAudioInputStream(new java.io.File(PanelChat.class.getResource("ring tone - Kalimbist.wav").toURI().getPath())));
                    clip.start();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

    public void addMessageToTop(MessageObject message){
        try{
            if (messages.containsKey(message.messagenumber)){
                System.out.println("Message already exists");
                return;
            }
            if (currentmin == -1 || currentmin > message.messagenumber) currentmin = message.messagenumber;
            if (currentmax == -1 || currentmax < message.messagenumber) currentmax = message.messagenumber;
            this.loadedmessagenumber = message.messagenumber;
            AFChatItem chatItem = new AFChatItem(message);
            messages.put(message.messagenumber, chatItem);
            panelChat.add(ChatLayout.createChatItemBox(chatItem), 1);
            chatItem.setShowDetail(false);
            chatItem.updateDateTime();
            
            if (message.type == 3 || !messages.containsKey(message.messagenumber - 1) || messages.get(message.messagenumber - 1).messageObject.type == 3 || (message.timesent.getTime()/1000 - messages.get(message.messagenumber - 1).messageObject.timesent.getTime()/1000) > timi)
            {
                chatItem.setShowDetail(true);
                if (messages.containsKey(message.messagenumber + 1)){
                    if (messages.get(message.messagenumber + 1).messageObject.type == 3 || (messages.get(message.messagenumber - 1).messageObject.timesent.getTime()/1000 - message.timesent.getTime()/1000 ) > timi){
                        messages.get(message.messagenumber + 1).setShowDetail(false);
                    }
                }
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

    public void loadMessages(List<MessageObject> messageObjects) {
        isLoadingOldMessages = true;
        long currentMinChat = currentmin;
        for(MessageObject messageObject: messageObjects){
            addMessageToTop(messageObject);
        }
        if (panelChat.getComponentCount() > messageObjects.size()){
            Box currentBox = (Box)messages.get(currentMinChat).getParent();
            // scroll panelChat to the top of the current box
            panelChatScroll.getVerticalScrollBar().setValue(currentBox.getY());
            current_vertical_value = panelChatScroll.getVerticalScrollBar().getValue();

        }
        isLoadingOldMessages = false;
    }

    public void removeMessagePassively(long messagenumber){
        byte type = messages.get(messagenumber).messageObject.type;
        panelChat.remove(messages.get(messagenumber).getParent());
        messages.remove(messagenumber);
        String id1 = AFriendClient.user.id;
        String id2 = this.id;
        if (type == 3){
            // set filesOnCancel id1+"_"+id2+"_"+messageNumber to true
            String fileId = id1 + "_" + id2 + "_" + messagenumber;
            AFriendClient.filesOnCancel.put(fileId, true);
        }
    }

    public void scrollToBottom() {
        if (this.panelChat.getComponentCount() > 1){
            this.panelChatScroll.getVerticalScrollBar().setValue(panelChatScroll.getVerticalScrollBar().getMaximum());
        }
    }
    
    public void LoadMessage(){
        AFriendClient.queueCommand(("6475" + this.id + "0120").getBytes(StandardCharsets.UTF_16LE));
    }

    public void addMessage(String text, boolean isMine, int position) {
        
        AFChatItem chatItem2 = new AFChatItem(text, isMine);
        if (position <= 0) position = panelChat.getComponentCount();
        panelChat.add(ChatLayout.createChatItemBox(chatItem2), position);
        //panelChat.revalidate();
    }

    public static void main(String[] args){
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                } catch (Exception ex) {
                   ex.printStackTrace();
                }
                JFrame frame = new JFrame();
                frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                frame.setBounds(100, 100, 912, 681);;
                PanelChat p = new PanelChat();
                frame.add(p);
                frame.setVisible(true);
                p.addMessage("Hello", true, 0);
                p.addMessage("World", false, 1);
            }
        });
    }

    public void setAvatar(Image img) {
        this.avatar = img;
        this.friendPicture.setImage(new ImageIcon(this.avatar.getScaledInstance(friendPicture.getWidth(), friendPicture.getHeight(), Image.SCALE_SMOOTH)));
        this.friendPicture.repaint();
    }
}
