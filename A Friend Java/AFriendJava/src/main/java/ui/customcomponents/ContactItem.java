package ui.customcomponents;

import java.awt.Color;
import java.awt.Image;
import java.awt.event.ComponentEvent;
import java.awt.event.MouseEvent;
import java.awt.Dimension;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;

import com.mycompany.afriendjava.Account;
import com.mycompany.afriendjava.MainUI;

public class ContactItem extends JComponent{

    public static void main(String[] args) {
        // create a jframe and add this ContactItem to it
        JFrame frame = new JFrame();
        frame.setBounds(100, 100, 800, 800);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(null);
        ContactItem contact = new ContactItem("Ai cũng đc", "ê thằng kia", true);
        frame.getContentPane().add(contact);
        contact.setLocation(0,0);
        
        frame.setVisible(true);
    }

    public Image avatar;
    public Image defaultFriendPicture = (new ImageIcon(getClass().getResource("/com/mycompany/afriendjava/Resources/newUser.png"))).getImage();

    public String id;
    private JLabel labelLastMessage;
    private JLabel labelName;
    private custom.CircleAvatar friendPicture;
    public boolean clicked;
    private boolean mouseOn;
    private byte state;
    private Color stateColor = Color.decode("#DCDCDC");
    private boolean unread;
    private Account account;

    

    public byte getState(){ return state; }
    public void setState(byte state){ 
        if (this.state != state){
            this.state = state;

            if (this.state == 0){
                this.stateColor = Color.decode("#DCDCDC");
            }
            else if (this.state == 1){
                this.stateColor = Color.decode("#00FF7F");
            }
            else{
                this.stateColor = Color.decode("#FF0000");
            }
            this.friendPicture.setBorderColor(stateColor);
            this.friendPicture.revalidate();
            this.friendPicture.repaint();
            this.revalidate();
            this.repaint();
        }
     }

    public void setUnread(boolean b) {
        unread = b;
        if (unread){
            labelLastMessage.setForeground(new Color(65, 165, 238));
        }
        else {
            labelLastMessage.setForeground(Color.decode("#696969"));
        }
    }

    public boolean getUnread(){
        return unread;
    }

    public String getFriendName(){
        return account.name;
    }

    public void setFriendName(String name){
        labelName.setText(name);
    }

    public ContactItem(Account account){
        initializeComponent();
        this.account = account;
        this.setDoubleBuffered(true);
        this.setName("contacItem_" + account.id);
        this.setFriendName(account.name);
        this.id = account.id;
        this.setState(account.state);
        this.revalidate();
        this.repaint();
        //TODO double click event
    }

    public void setLastMessage(String message){
        labelLastMessage.setText(message);
        labelLastMessage.revalidate();
        labelLastMessage.repaint();
    }

    public ContactItem(String name, String lastmessage, boolean unread){
        initializeComponent();
        labelName.setText(name);
        labelLastMessage.setText(lastmessage);
        setUnread(unread);
    }
    
    public ContactItem(){
        initializeComponent();
    }

    private void initializeComponent() {
        labelLastMessage = new JLabel();
        labelName = new JLabel();
        friendPicture = new custom.CircleAvatar();

        // label last message
        labelLastMessage.setBackground(new Color(0f, 0f, 0f, 1f));
        labelLastMessage.setForeground(Color.decode("#696969"));
        // set font to arial, regular, 11
        labelLastMessage.setFont(new java.awt.Font("Arial", 0, 11));
        // set location to 75 36
        labelLastMessage.setLocation(75, 36);
        // set maximumsize to 197 20
        labelLastMessage.setMaximumSize(new java.awt.Dimension(197, 20));
        // set minimumsize to 197 20
        labelLastMessage.setMinimumSize(new java.awt.Dimension(197, 20));
        // set size to 197 20
        labelLastMessage.setSize(197, 20);
        // set text to "You: last text here"
        labelLastMessage.setText("You: last text here");
        // add resize event
        labelLastMessage.addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentResized(java.awt.event.ComponentEvent evt) {
                labelLastMessageComponentResized(evt);
            }
        });
        // set click event
        /*
        labelLastMessage.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                labelLastMessageMouseClicked(evt);
            }
            @Override
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                labelLastMessageMouseEntered(evt);
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent evt) {
                labelLastMessageMouseExited(evt);
            }
        });
        */

        // label name
        labelName.setBackground(new Color(0f, 0f, 0f, 1f));
        // set font to arial, regular, 11
        labelName.setFont(new java.awt.Font("Arial", 0, 12));
        // set location to 75 36
        labelName.setLocation(75, 13);
        // set maximumsize to 197 20
        labelName.setMaximumSize(new java.awt.Dimension(197, 20));
        // set minimumsize to 197 20
        labelName.setMinimumSize(new java.awt.Dimension(197, 20));
        // set size to 197 20
        labelName.setSize(197, 20);
        // set text to "You: last text here"
        labelName.setText("Friend name");
        // set click event
        /*
        labelName.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                labelNameMouseClicked(evt);
            }
            @Override
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                labelNameMouseEntered(evt);
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent evt) {
                labelNameMouseExited(evt);
            }
        });
        */
        // add resize event
        labelName.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent evt) {
                labelNameComponentResized(evt);
            }
        });

        // friend picture
        friendPicture.setBackground(new Color(0f, 0f, 0f, 1f));
        friendPicture.setBorderColor(Color.decode("#DCDCDC"));
        friendPicture.setBorderSize(2);
        friendPicture.setLocation(20, 20);
        friendPicture.setSize(45, 45);
        friendPicture.setImage(new ImageIcon(defaultFriendPicture.getScaledInstance(45, 45, Image.SCALE_SMOOTH)));
        // add click event
        /*
        friendPicture.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                friendPictureMouseClicked(evt);
            }
            @Override
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                friendPictureMouseEntered(evt);
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent evt) {
                friendPictureMouseExited(evt);
            }
        });
        */

        // contact item
        setBackground(new Color(1f, 1f, 1f, 0f));
        // set padding
        setBorder(new javax.swing.border.EmptyBorder(10, 5, 10, 5));
        // set font
        setFont(new java.awt.Font("Microsoft Sans Serif", 0, 12));
        // set size
        setSize(300, 65);
        // add all components
        add(labelLastMessage);
        add(labelName);
        add(friendPicture);
        // set click event
        addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                itemMouseClicked(evt);
            }
            @Override
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                itemMouseEntered(evt);
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent evt) {
                itemMouseExited(evt);
            }
        });
    }

    protected void labelLastMessageComponentResized(ComponentEvent evt) {
        // print
        //System.out.println("labelLastMessage ComponentResized");
    }
    @Override
    protected void paintComponent(java.awt.Graphics g){
        Graphics2D g2d = (Graphics2D) g.create();
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        //g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
        //g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        if (clicked){
            g2d.setColor(new Color(255, 202, 152, 95));
            g2d.fillRect(10, 2, this.getWidth() - 20, this.getHeight() - 4);

        }
        else if (mouseOn){
            g2d.setColor(new Color(255, 202, 152, 50));
            g2d.fillRect(10, 2, this.getWidth() - 20, this.getHeight() - 4);
        }
        //g2d.setColor(stateColor);
        //g2d.drawOval(friendPicture.getX() - 1, friendPicture.getY() - 1 , friendPicture.getWidth() + 1 , friendPicture.getHeight() + 1);
    }

    @Override
    public Dimension getPreferredSize() {
        return new Dimension(300, 65);
    }

    @Override
    public Dimension getMinimumSize() {
        return new Dimension(300, 65);
    }

    @Override
    public Dimension getMaximumSize() {
        return new Dimension(300, 65);
    }

    protected void itemMouseEntered(MouseEvent evt) {
        mouseOn = true;
        repaint();
        //System.out.println("item mouse entered");
    }

    protected void itemMouseExited(MouseEvent evt) {
        mouseOn = false;
        repaint();
        // print
        //System.out.println("item Mouse exited");
    }

    protected void itemMouseClicked(MouseEvent evt) {
        clicked = true;
        repaint();
        if (this.getParent().getParent().getParent().getParent().getParent().getParent().getParent().getParent().getParent() instanceof MainUI){
            MainUI parent = (MainUI) this.getParent().getParent().getParent().getParent().getParent().getParent().getParent().getParent().getParent();
            if (parent.currentContactItem != null && parent.currentContactItem != this){
                parent.currentContactItem.clicked = false;
                parent.currentContactItem.repaint();
            }
            parent.currentContactItem = this;
        }

    }

    protected void friendPictureMouseExited(MouseEvent evt) {
        // print
        System.out.println("friend picture Mouse exited");
    }

    protected void friendPictureMouseEntered(MouseEvent evt) {
        // print
        System.out.println("friend picture Mouse entered");
    }

    protected void friendPictureMouseClicked(MouseEvent evt) {
        // print
        System.out.println("friend picture clicked");
    }

    protected void labelNameComponentResized(ComponentEvent evt) {
        // print
        System.out.println("label name component resized");
    }

    protected void labelNameMouseExited(MouseEvent evt) {
        // print
        System.out.println("label name Mouse exited");
    }

    protected void labelNameMouseEntered(MouseEvent evt) {
        // print
        System.out.println("label name Mouse entered");
    }

    protected void labelNameMouseClicked(MouseEvent evt) {
        // print
        System.out.println("label name clicked");
    }

    protected void labelLastMessageMouseExited(MouseEvent evt) {
        // print
        System.out.println("label last message Mouse exited");
    }

    protected void labelLastMessageMouseEntered(MouseEvent evt) {
        // print
        System.out.println("label last message Mouse entered");
    }

    protected void labelLastMessageMouseClicked(MouseEvent evt) {
        // print
        System.out.println("label last message clicked");
    }
    public void setAvatar(Image img) {
        this.avatar = img;
        this.friendPicture.setImage(new ImageIcon(img.getScaledInstance(this.friendPicture.getWidth(), this.friendPicture.getHeight(), Image.SCALE_SMOOTH)));
    }
}
