package ui.customcomponents;

import java.awt.Color;
import java.awt.event.ComponentEvent;
import java.awt.geom.Arc2D;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;

public class MessagePanel extends JPanel{
    public static void main(String[] args){
        JFrame frame = new JFrame();
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(500, 500);
        frame.setLayout(null);

        MessagePanel panel = new MessagePanel();
        panel.setBounds(100, 200, 200, 100);
        
        JButton button = new JButton("alo");
        button.setBounds(50, 25, 100, 50);
        panel.add(button);

        frame.add(panel);
        frame.setVisible(true);

    }  

    public MessagePanel(){
        //this.setLayout(null); // only uncomment this for debug
        this.setOpaque(false);
        //this.setBackground(new Color(0, 0, 255));
        this.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent evt) {
                messagePanelResized(evt);
            }
        });
    }

    protected void messagePanelResized(ComponentEvent evt) {
        this.repaint();
    }

    int borderRadius = 20;

    public Color backColor = new Color(141, 161, 252);

    @Override
    protected void paintComponent(java.awt.Graphics g) {
        super.paintComponent(g);
        java.awt.Graphics2D g2 = (java.awt.Graphics2D) g;
        g2.setColor(backColor);
        java.awt.Rectangle clientRectangle = this.getBounds();
        float thickness = 2;
        java.awt.Stroke oldStroke = g2.getStroke();
        g2.setStroke(new java.awt.BasicStroke(thickness));
        //g.drawRect(clientRectangle.x, clientRectangle.y, clientRectangle.width, clientRectangle.height);
        Arc2D arc3 = new Arc2D.Double(0, clientRectangle.height - borderRadius, borderRadius, borderRadius, 180, 90, Arc2D.OPEN);
        Arc2D arc4 = new Arc2D.Double(clientRectangle.width - borderRadius, clientRectangle.height - borderRadius, borderRadius, borderRadius, 270, 90, Arc2D.OPEN);
        Arc2D arc1 = new Arc2D.Double(clientRectangle.width - borderRadius, 0, borderRadius, borderRadius, 0, 90, Arc2D.OPEN);
        Arc2D arc2 = new Arc2D.Double(0, 0, borderRadius, borderRadius, 90, 90, Arc2D.OPEN);
        java.awt.geom.GeneralPath shape = new java.awt.geom.GeneralPath();
        shape.append(arc1, true);
        shape.append(arc2, true);
        shape.append(arc3, true);
        shape.append(arc4, true);
        //g2.draw(shape);
        g2.fill(shape);
        g2.setStroke(oldStroke);
    }
}
