package com.mycompany.afriendjava;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Image;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Set;
import java.util.TreeMap;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import java.awt.event.*;

import com.mycompany.afriendjava.custom.TextField;
import java.awt.AWTException;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import ui.customcomponents.*;

import javax.swing.SwingConstants;
import javax.swing.UIManager;

public class MainUI extends javax.swing.JFrame {
    
    static int He;
    static int We;
    Dimension d;
    Dimension dMin;
    // variables
    public PanelChat currentPanelChat;
    public HashMap<String, PanelChat> panelChats = new HashMap<String, PanelChat>();
    public HashMap<String, ContactItem> contactItems = new HashMap<String, ContactItem>();
    public TreeMap<Integer, String> orderOfContactItems = new TreeMap<Integer, String>();
    
    public static ConcurrentHashMap<String, JFrame> subForms = new ConcurrentHashMap<String, JFrame>();
    public static String currentID;

    private boolean check = true;
    private String searchText = "";
    public boolean loaded = false;
    private boolean priv = false;
    private boolean logout = false;

    // forms
    // private FormContactRemoved formContactRemoved = new FormContactRemoved();
    // private FormGetStarted formGetStarted = new FormGetStarted();
    public Loading formLoading = new Loading();
    public Settings formSettings = null;
    //public FormAddContact formAddContact = new FormAddContact();
    public JPanel panelLoading = new JPanel();

    // initialization    
    public Image appIcon = (new ImageIcon(getClass().getResource("/com/mycompany/afriendjava/Resources/logo.png"))).getImage();
    Image trayIconImage = (new ImageIcon(getClass().getResource("/com/mycompany/afriendjava/Resources/logo.png"))).getImage();
    Image addIcon = (new ImageIcon(getClass().getResource("/com/mycompany/afriendjava/Resources/Add.png"))).getImage();
    Image settingIcon = (new ImageIcon(getClass().getResource("/com/mycompany/afriendjava/Resources/Cogs.png"))).getImage();
    Image logoutIcon = (new ImageIcon(getClass().getResource("/com/mycompany/afriendjava/Resources/sign-out-option.png"))).getImage();
    Image addGroupIcon = (new ImageIcon(getClass().getResource("/com/mycompany/afriendjava/Resources/plus_add_insert_icon_1779051.png"))).getImage();

    final TrayIcon trayIcon = new TrayIcon(trayIconImage, "A Friend");
    final PopupMenu popup = new PopupMenu();
    SystemTray tray = null;

    private WindowAdapter closeAdapter = new WindowAdapter() {
        @Override
        public void windowClosing(WindowEvent e) {
            if (SystemTray.isSupported()){
                try 
                {
                    tray.add(trayIcon);
                } catch (AWTException ex) {
                    ex.printStackTrace();
                }
            }
            else{
                MainUI.this.dispatchEvent(new WindowEvent(MainUI.this, WindowEvent.WINDOW_ICONIFIED));
            }
        }
    };

    private JPanel ContactList_Panel;
    private JPanel ContactList_Panel2;
    private JPanel panelLeft;
    private JPanel panelRight;
    private JPanel panelRight2;
    private JPanel panelTopLeft;
    private JScrollPane ContactList_ScrollPanel;
    private JPanel panelAdd;
    private JPanel Button_Panel;
    private JButton LogOut_Button;
    private JButton Setting_Button;
    private JButton AddFriend_Button;
    private JTextField SearchBar;
    private JButton AddGroup_Button;
    private JLabel labelWarning;
    private JTextField txtNewUser;
    // end initialization

    public ContactItem currentContactItem;


    public boolean isThisPersonAdded(String id) {
        return contactItems.containsKey(id);
    }
    public synchronized void sortContactItems(){
        try{
            int length = contactItems.size();
            for(int i = 0; i < length; i++){
                String min = "";
                int j = 0;
                for(Entry<Integer, String> keyValuePair: orderOfContactItems.entrySet()){
                    if (j == length){
                        break;
                    }
                    if (min == ""){
                        min = keyValuePair.getValue();
                    }
                    else
                    {
                        if (panelChats.get(min).DateTimeOfLastMessage().getTime() > panelChats.get(keyValuePair.getValue()).DateTimeOfLastMessage().getTime()){
                            min = keyValuePair.getValue();
                        }
                    }
                    j = j + 1;
                }
                length = length - 1;
                bringContactItemToTop(min);
            }

            for(Entry<Integer, String> keyValuePair1: orderOfContactItems.entrySet()){
                ContactList_Panel.add(ContactLayout.createContactItemBox(contactItems.get(keyValuePair1.getValue())), ContactList_Panel.getComponentCount() - 1);
            }

            ContactList_Panel.revalidate();
            ContactList_Panel.repaint();
            ContactList_ScrollPanel.revalidate();
            ContactList_ScrollPanel.repaint();

            loaded = true;

            formLoading.stopSpinning();
            formLoading.setVisible(false);
            formLoading.dispose();
            this.setVisible(true);

            //panelLoading.toBack(); //how?
            formLoading.stopSpinning();
            formLoading.dispose();
            panelLoading.setVisible(false);

            if(panelChats.size() > 0){
                showPanelChat(orderOfContactItems.lastEntry().getValue(), false);
                panelChats.get(orderOfContactItems.lastEntry().getValue()).scrollToBottom();
                this.currentContactItem = contactItems.get(orderOfContactItems.lastEntry().getValue());
                this.currentContactItem.clicked = true;
                this.currentContactItem.repaint();
            }
            else {
                // clear controls of chat panel
                panelRight.removeAll();
                SearchBar.setVisible(false);
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
    public void bringContactItemToTop(String id) {
        if (orderOfContactItems.size() <= 1){
            return;
        }
        int key = -1;
        for(Entry<Integer, String> keyValuePair: orderOfContactItems.entrySet()){
            if (keyValuePair.getValue().equals(id)){
                key = keyValuePair.getKey();
                break;
            }
        }

        if (key != -1){
            orderOfContactItems.remove(key);
            orderOfContactItems.put(orderOfContactItems.lastKey() + 1, id);
        }

        if (loaded){
            ui.customcomponents.ContactItem item = contactItems.get(id);
            if (searchText == ""){
                System.out.println(ContactList_Panel.getComponentZOrder(item.getParent()));
                ContactList_Panel.remove(item.getParent());
                ContactList_Panel.add(item.getParent(), ContactList_Panel.getComponentCount() -1);
            }
        }
    }
    public synchronized void setAvatar(String id, Image img){
        if(panelChats.containsKey(id)){
            panelChats.get(id).setAvatar(img);
            contactItems.get(id).setAvatar(img);
            contactItems.get(id).repaint();
        }
    }
    public synchronized void showLogin(){
        for(JFrame f: subForms.values()){
            f.dispose();
        }
        this.dispose();
        Login lg = new Login();
        lg.setVisible(true);
        Program.mainform = null;
        try{
            if (AFriendClient.user != null){
                AFriendClient.user.state = 0;
            }
        }
        catch(Exception e){
            AFriendClient.user = null;
        }
    }
    public synchronized void showPanelChat(String id, boolean force){
        ui.customcomponents.PanelChat item = panelChats.get(id);
        if (panelRight.getComponentCount() == 0)
        {
            if (force || (getCurrentPanelChatId() == "" || !(panelRight2.getComponent(0) instanceof PanelChat) || ((PanelChat) panelRight2.getComponent(0)).id != id)){
                panelRight.add(item, BorderLayout.CENTER);
                //item.setSize(panelRight.getSize());
                panelRight.setVisible(true);
                panelRight2.setVisible(false);
                panelRight2.removeAll();
                panelRight.revalidate();
                panelRight.repaint();
                panelRight2.revalidate();
                panelRight2.repaint();
                System.out.println("panelRight displaying" + id);
            }
        }
        else{
            if (force || (getCurrentPanelChatId() == "" || !(panelRight.getComponent(0) instanceof PanelChat) || ((PanelChat) panelRight.getComponent(0)).id != id)){
                panelRight2.add(item, BorderLayout.CENTER);
                //item.setSize(panelRight2.getSize());
                panelRight2.setVisible(true);
                panelRight.setVisible(false);
                panelRight.removeAll();
                panelRight.revalidate();
                panelRight.repaint();
                panelRight2.revalidate();
                panelRight2.repaint();
                System.out.println("panelRight2 displaying" + id);
            }
        }
        currentID = id;
        currentPanelChat = item;
        item.scrollToBottom();
    }
    private String getCurrentPanelChatId(){
        if (panelRight.getComponentCount() > 0){
            if (panelRight.getComponent(0) instanceof PanelChat){
                return ((PanelChat) panelRight.getComponent(0)).id;
            }
        }
        if (panelRight2.getComponentCount() > 0){
            if (panelRight2.getComponent(0) instanceof PanelChat){
                return ((PanelChat) panelRight2.getComponent(0)).id;
            }
        }
        
        return "";
    }
    public synchronized void removeContact(String id){
        if (!panelChats.containsKey(id) || !contactItems.containsKey(id))
            return;
        ContactList_Panel.remove(contactItems.get(id).getParent());
        ContactList_Panel.revalidate();
        ContactList_Panel2.remove(contactItems.get(id).getParent());
        ContactList_Panel2.revalidate();

        if (panelRight.getComponent(0) == panelChats.get(id)){
            panelRight.removeAll();
            panelRight.setVisible(false);
            panelRight.revalidate();
            panelRight.repaint();
            panelRight2.setVisible(true);
            if (panelRight2.getComponentCount() > 0){
                currentPanelChat = (PanelChat) panelRight2.getComponent(0);
                currentID = currentPanelChat.id;
                currentContactItem = contactItems.get(currentID);
                currentContactItem.clicked = true;
                currentContactItem.repaint();
            }
            panelRight2.revalidate();
            panelRight2.repaint();
        }
        else if (panelRight2.getComponent(0) == panelChats.get(id)){
            panelRight2.removeAll();
            panelRight2.setVisible(false);
            panelRight2.revalidate();
            panelRight2.repaint();
            panelRight.setVisible(true);
            if (panelRight.getComponentCount() > 0){
                currentPanelChat = (PanelChat) panelRight.getComponent(0);
                currentID = currentPanelChat.id;
                currentContactItem = contactItems.get(currentID);
                currentContactItem.clicked = true;
                currentContactItem.repaint();
            }
            panelRight.revalidate();
            panelRight.repaint();
        }

        panelChats.remove(id);
        contactItems.remove(id);
        for(Entry<Integer, String> entry: orderOfContactItems.entrySet()){
            if (entry.getValue().equals(id)){
                orderOfContactItems.remove(entry.getKey());
                break;
            }
        }
    }
    public synchronized void addContactItem(Account acc){
        try{
            if (!panelChats.containsKey(acc.id)){
                System.out.println("add contact item");
                ContactItem ci = new ContactItem(acc);
                ci.setUnread(true);
                if (loaded){
                    ContactList_Panel.add(ContactLayout.createContactItemBox(ci), 0);
                }
                System.out.println("added");
                if (orderOfContactItems.size() == 0){
                    orderOfContactItems.put(0, acc.id);
                }
                else{
                    orderOfContactItems.put(orderOfContactItems.lastKey() + 1, acc.id);
                }

                if (loaded){
                    // scroll ContactList_Panel to where the new contact item is
                    ContactList_ScrollPanel.getVerticalScrollBar().setValue(ci.getParent().getLocation().y);
                }
                contactItems.put(acc.id, ci);
                PanelChat panelChat = new PanelChat(acc);
                panelChats.put(acc.id, panelChat);
                //System.out.println(ci.getVisibleRect().toString());
                //System.out.println(((Box)ci.getParent()).getVisibleRect().toString());
                ContactList_Panel.revalidate();
                ContactList_Panel.repaint();
                panelChat.panelChat.addContainerListener(new ContainerAdapter() {
                    @Override
                    public void componentAdded(ContainerEvent e) {
                        if (panelChat.panelChat.getComponentCount() > 1){
                            ci.setLastMessage(panelChat.getLastMessage());
                        }
                        if (loaded && !panelChat.isLastMessageFromYou()){
                            ci.setUnread(true);
                        }
                        if (ci.id != orderOfContactItems.lastEntry().getValue()){
                            if (!panelChat.isLoadingOldMessages){
                                bringContactItemToTop(panelChat.id);
                            }
                        }
                    }

                    @Override
                    public void componentRemoved(ContainerEvent e) {
                        ci.setLastMessage(panelChat.getLastMessage());
                    }
                });

                ci.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        if (e.getButton() == MouseEvent.BUTTON1){
                            if (e.getClickCount() == 1){
                                if (!MainUI.subForms.containsKey(panelChat.id)){
                                    showPanelChat(acc.id, false);
                                    System.out.println("Clicked");
                                }
                            }
                        }
                    }
                });

                panelChat.LoadMessage();
                panelChat.scrollToBottom();

                //ci.setLastMessage(panelChat.getLastMessage());
            }
        }
        catch (Exception e){
            e.printStackTrace();
            throw e;
        }
    }
    public synchronized void turnContactActiveState(String id, byte state){
        if (panelChats.containsKey(id)){
            panelChats.get(id).setState(state);
        }

        if (contactItems.containsKey(id)){
            contactItems.get(id).setState(state);
        }
    }

    public synchronized void changeWarning(String text, Color color){
        labelWarning.setText(text);
        labelWarning.setForeground(color);
    }
    /**
     * Creates new form Main
     */
    public MainUI() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ex) {
           ex.printStackTrace();
        }
        initComponents();
        initSubPanels();

    	setTitle("A Friend Chat App");
    	setIconImage(appIcon);

        //take screen size
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        int width = screenSize.width;
        int height = screenSize.height;
        this.setBounds(width/4, height/4, width/2, height/2);
        formLoading.setBounds(width/4, height/4, width/2, height/2);
        formLoading.setVisible(true);
        this.AddFriend_Button.doClick();
        //getContentPane().setBackground(new Color(0, 205, 205));

    }

    private void initSubPanels() {
        
        ContactList_Panel2 = new JPanel();
        ContactList_Panel2.setLayout(new BoxLayout(ContactList_Panel2, BoxLayout.Y_AXIS));
        ContactList_Panel2.setBackground(ContactList_Panel.getBackground());
        ContactList_Panel2.setBorder(ContactList_Panel.getBorder());
        //ContactList_Panel2.setVisible(false);
        ContactList_Panel2.setMinimumSize(new Dimension(ContactList_Panel.getMinimumSize().width, ContactList_Panel.getMinimumSize().height));
        ContactList_Panel2.setSize(ContactList_Panel.getWidth(), ContactList_Panel.getHeight());
        ContactList_Panel2.setLocation(0, 0);
        //this.add(ContactList_Panel2);
        

    }
    private void initComponents(){

        AddFriend_Button = new JButton();
        AddFriend_Button.setMinimumSize(new Dimension(40, 40));
        AddFriend_Button.setMaximumSize(new Dimension(40, 40));
        AddFriend_Button.setLocation(110, 10);
        AddFriend_Button.setSize(40, 40);
        AddFriend_Button.setIcon(new ImageIcon(addIcon.getScaledInstance(AddFriend_Button.getWidth(), AddFriend_Button.getHeight(), Image.SCALE_SMOOTH)));
        AddFriend_Button.setVisible(true);
        AddFriend_Button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                addFriend(e);
            }
        });
        
        Setting_Button = new JButton("");
        Setting_Button.setMinimumSize(new Dimension(40, 40));
        Setting_Button.setMaximumSize(new Dimension(40, 40));
        Setting_Button.setLocation(60, 10);
        Setting_Button.setSize(40, 40);
        Setting_Button.setIcon(new ImageIcon(settingIcon.getScaledInstance(Setting_Button.getWidth(), Setting_Button.getHeight(), Image.SCALE_SMOOTH)));
        Setting_Button.setVisible(true);
        Setting_Button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                setting(e);
            }
        });
        
        LogOut_Button = new JButton("");
        LogOut_Button.setMinimumSize(new Dimension(40, 40));
        LogOut_Button.setMaximumSize(new Dimension(40, 40));
        LogOut_Button.setLocation(10, 10);
        LogOut_Button.setSize(40, 40);
        LogOut_Button.setIcon(new ImageIcon(logoutIcon.getScaledInstance(LogOut_Button.getWidth(), LogOut_Button.getHeight(), Image.SCALE_SMOOTH))); 
        LogOut_Button.setVisible(true);
        LogOut_Button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                logout(e);
            }
        });

        
        
        AddGroup_Button = new JButton("");
        AddGroup_Button.setMinimumSize(new Dimension(40, 40));
        AddGroup_Button.setMaximumSize(new Dimension(40, 40));
        AddGroup_Button.setLocation(160, 10);
        AddGroup_Button.setSize(40, 40);
        AddGroup_Button.setIcon(new ImageIcon(addGroupIcon.getScaledInstance(AddGroup_Button.getWidth(), AddGroup_Button.getHeight(), Image.SCALE_SMOOTH)));
        AddGroup_Button.setVisible(true);
        AddGroup_Button.addActionListener(new ActionListener(){
            @Override
            public void actionPerformed(ActionEvent e) {
                addGroup(e);
            }
        });

        
        SearchBar = new JTextField();
        SearchBar.setBackground(Color.WHITE);
        SearchBar.setLocation(22, 9);
        SearchBar.setSize(258, 43);
        SearchBar.setOpaque(true);
        // text change listener
        SearchBar.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                search(e);
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                search(e);
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                search(e);
            }
        });
        TextPrompt tpSearch = new TextPrompt("Search", SearchBar);
        
        panelTopLeft = new JPanel(){
            @Override
            protected void paintComponent(java.awt.Graphics g) {
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g.create();
                // set color to gray
                g2d.setColor(Color.decode("#808080"));
                // set width of the line
                g2d.setStroke(new BasicStroke(1));
                // draw line
                g2d.drawLine(0, getHeight() - 1, getWidth(), getHeight() -1);
            }
        };
        panelTopLeft.setOpaque(true);
        panelTopLeft.setBackground(new Color(60, 141, 138));
        panelTopLeft.setLocation(0, 0);
        panelTopLeft.setSize(300, 60);
        panelTopLeft.setLayout(null);
        panelTopLeft.add(SearchBar);
        
        ContactList_Panel = new JPanel();
        ContactList_Panel.setLayout(new BoxLayout(ContactList_Panel, BoxLayout.Y_AXIS));
        ContactList_Panel.setLocation(0,0);
        ContactList_Panel.setMinimumSize(new Dimension(0, 0));
        ContactList_Panel.setSize(300, 514);
        ContactList_Panel.setBackground(new Color(247, 249, 255));
        ContactList_Panel.setVisible(true);
        ContactList_Panel.add(Box.createVerticalGlue());
        
        ContactList_ScrollPanel = new JScrollPane(ContactList_Panel);
        ContactList_ScrollPanel.setLocation(0, 60);
        ContactList_ScrollPanel.setBorder(null);
        ContactList_ScrollPanel.setDoubleBuffered(true);
        ContactList_ScrollPanel.setSize(300, 514);
        ContactList_ScrollPanel.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        ContactList_ScrollPanel.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        // scrollbar speed
        ContactList_ScrollPanel.getVerticalScrollBar().setUnitIncrement(19);

        labelWarning = new JLabel();
        labelWarning.setOpaque(true);
        labelWarning.setBackground(new Color(247, 249, 255));
        labelWarning.setLocation(0, 52);
        labelWarning.setSize(295, 25);
        // set font to microsoft sans serif, 10f, regular, gdicharset = 163
        labelWarning.setFont(new Font("Microsoft Sans Serif", Font.PLAIN, 14));
        labelWarning.setForeground(Color.RED);
        // align text to center
        labelWarning.setHorizontalAlignment(JLabel.CENTER);
        labelWarning.setText("This user does not exist");

        txtNewUser = new JTextField();
        txtNewUser.setBackground(Color.WHITE);
        txtNewUser.setLocation(17, 6);
        txtNewUser.setSize(263, 38);
        txtNewUser.setOpaque(true);
        // enter key listener
        txtNewUser.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    addNewUser(e);
                }
            }
        });

        panelAdd = new JPanel();
        panelAdd.setOpaque(true);
        panelAdd.setLocation(0, 574);
        panelAdd.setSize(300, 78);
        panelAdd.setBackground(new Color(247, 249, 255));
        panelAdd.setLayout(null);
        panelAdd.add(txtNewUser);
        panelAdd.add(labelWarning);
        
        Button_Panel = new JPanel();
        Button_Panel.setOpaque(true);
        Button_Panel.setBackground(new Color(230, 244, 241));
        Button_Panel.setLocation(0, 652);
        Button_Panel.setSize(300, 60);
        Button_Panel.setDoubleBuffered(true);
        Button_Panel.setLayout(null);
        Button_Panel.add(LogOut_Button);
        Button_Panel.add(Setting_Button);
        Button_Panel.add(AddFriend_Button);
        //Button_Panel.add(AddGroup_Button);

        panelLeft = new JPanel();
        panelLeft.setLocation(0, 0);
        panelLeft.setSize(300, 712);
        panelLeft.setBackground(Color.white);
        panelLeft.setLayout(null);
        panelLeft.add(panelTopLeft);
        panelLeft.add(ContactList_ScrollPanel);
        panelLeft.add(panelAdd);
        panelLeft.add(Button_Panel);
        panelLeft.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                int height = e.getComponent().getHeight();
                int width = e.getComponent().getWidth();
                ContactList_ScrollPanel.setSize(width, height - panelTopLeft.getHeight() - Button_Panel.getHeight() - (panelAdd.isVisible()?panelAdd.getHeight():0));
                panelAdd.setLocation(0, ContactList_ScrollPanel.getY() + ContactList_ScrollPanel.getHeight());
                Button_Panel.setLocation(0, height - Button_Panel.getHeight());
                e.getComponent().revalidate();
                e.getComponent().repaint();
            }
        });
        
        panelRight = new JPanel();        
        panelRight.setLocation(350,0);
        panelRight.setBackground(Color.white);
        panelRight.setSize(getWidth() - 300, getHeight());
        // set layout so that this panelRight's content is always fill the panelRight's space
        panelRight.setLayout(new java.awt.BorderLayout());
        panelRight.setVisible(true);

        panelRight2 = new JPanel();
        panelRight2.setLocation(panelRight.getLocation());
        panelRight2.setSize(panelRight.getSize());
        panelRight2.setBackground(panelRight.getBackground());
        panelRight2.setLayout(new java.awt.BorderLayout());
        panelRight2.setVisible(false);
        
        this.setLayout(null);
        this.setMinimumSize(new Dimension(900,450));
        this.add(panelLeft);
        this.add(panelRight);
        this.add(panelRight2);
        this.setIconImage(appIcon);
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        
        //event
        addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent evt) {                                       
                int width = evt.getComponent().getWidth() - ((MainUI)evt.getComponent()).getInsets().right - ((MainUI)evt.getComponent()).getInsets().left;
                // height without frame's title bar
                int height = evt.getComponent().getHeight() - ((MainUI)evt.getComponent()).getInsets().top - ((MainUI)evt.getComponent()).getInsets().bottom;
                panelLeft.setBounds(0, 0, 300, height);
                panelRight.setBounds(300, 0, width - 300, height);
                panelRight2.setBounds(300, 0, width - 300, height);
            }         
        });

        // tray
        if (SystemTray.isSupported()){
            setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
            tray = SystemTray.getSystemTray();
            // create menu item for the default action
            MenuItem defaultItem = new MenuItem("Main menu");
            defaultItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    MainUI.this.setVisible(true);
                    // remove tray
                    tray.remove(trayIcon);
                }
            });
            popup.add(defaultItem);
            MenuItem quitItem = new MenuItem("Quit");
            quitItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    MainUI.this.removeWindowListener(MainUI.this.closeAdapter);
                    MainUI.this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                    MainUI.this.dispatchEvent(new WindowEvent(MainUI.this, WindowEvent.WINDOW_CLOSING));
                }
            });
            popup.add(quitItem);
            /// ... add other items
            // construct a TrayIcon
            trayIcon.setImageAutoSize(true);
            trayIcon.setPopupMenu(popup);
            // set the TrayIcon properties
            trayIcon.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    MainUI.this.setVisible(true);
                    tray.remove(trayIcon);
                }
            });
            addWindowListener(closeAdapter);
        }
        else {
            setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
            addWindowListener(closeAdapter);
        }
    }

    protected void addGroup(ActionEvent e) {
        AFriendClient.queueCommand("".getBytes(StandardCharsets.UTF_16LE));
    }
    protected void addNewUser(KeyEvent e) {
        String text = txtNewUser.getText();
        if (text.equals("")){
            changeWarning("Please enter username or ID", Color.RED);
            return;
        }
        boolean isId = true;
        if (text.length() == 19){
            // check if text only contains numbers
            for (int i = 0; i < text.length(); i++){
                if (!Character.isDigit(text.charAt(i))){
                    isId = false;
                    break;
                }
            }
        }
        else{
            isId = false;
        }
        if (isId){
            AFriendClient.queueCommand(("0609" + text).getBytes(StandardCharsets.UTF_16LE));
        }
        else {
            AFriendClient.queueCommand(("0610" + Tools.data_with_unicode_byte(text)).getBytes(StandardCharsets.UTF_16LE));
        }
    }
    protected void search(DocumentEvent e) {
        String text = SearchBar.getText().trim();
        if (text == searchText) return;
        searchText = text;
        if (searchText.equals("") || searchText.length() == 0){
            ContactList_Panel2.removeAll();
            ContactList_Panel.removeAll();
            ContactList_Panel.add(Box.createVerticalGlue());
            for( Entry <Integer, String> i : orderOfContactItems.entrySet()){
                ContactList_Panel.add(contactItems.get(i.getValue()).getParent(), ContactList_Panel.getComponentCount() - 1);
            }
            ContactList_ScrollPanel.setViewportView(ContactList_Panel);
        }
        else {
            ContactList_Panel2.removeAll();
            ContactList_Panel2.add(Box.createVerticalGlue());
            for(ContactItem contactItem: contactItems.values()){
                if (contactItem.getFriendName().toLowerCase().contains(searchText.toLowerCase())){
                    ContactList_Panel2.add(contactItem.getParent(), ContactList_Panel2.getComponentCount() - 1);
                }
            }
            ContactList_ScrollPanel.setViewportView(ContactList_Panel2);
        }
    }
    protected void logout(ActionEvent e) {
        AFriendClient.queueCommand(("2004").getBytes(StandardCharsets.UTF_16LE));
        for(JFrame f : subForms.values()){
            // for each component of the frame, dispose it out of memory
            f.dispose();
        }
        this.logout = true;
        panelChats.clear();
        Login lg = new Login();
        lg.setVisible(true);
        Program.mainform = null;
        try{
            if (AFriendClient.user != null){
                AFriendClient.user.state = 0;
            }
        }
        catch (Exception ex){
            System.out.println(ex.getMessage());
        }
        this.dispose();

    }
    protected void setting(ActionEvent e) {
        // show Settings Jframe dialog
        formSettings = new Settings();
        formSettings.setVisible(true);

    }
    protected void addFriend(ActionEvent e) {
        if (ContactList_ScrollPanel.getSize().height == Button_Panel.getY() - (ContactList_ScrollPanel.getY())) {
            ContactList_ScrollPanel.setSize(ContactList_ScrollPanel.getWidth(), ContactList_ScrollPanel.getHeight() - panelAdd.getHeight());
            panelAdd.setLocation(ContactList_ScrollPanel.getX(), ContactList_ScrollPanel.getY() + ContactList_ScrollPanel.getHeight());
            panelAdd.setVisible(true);
            panelAdd.revalidate();
            panelAdd.repaint();
        }
        else {
            ContactList_ScrollPanel.setSize(ContactList_ScrollPanel.getWidth(), ContactList_ScrollPanel.getHeight() + panelAdd.getHeight());
            panelAdd.setVisible(false);
            panelAdd.revalidate();
            panelAdd.repaint();
        }
    }
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(MainUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(MainUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(MainUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(MainUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }

        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
            	JFrame f = new MainUI();
                f.setVisible(true);
            }
        });
    }
}