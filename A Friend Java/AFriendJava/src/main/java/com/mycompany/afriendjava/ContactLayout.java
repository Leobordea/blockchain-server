package com.mycompany.afriendjava;

import javax.swing.Box;
import javax.swing.BoxLayout;

import ui.customcomponents.ContactItem;

import java.awt.Component;
import java.awt.Color;

public class ContactLayout{
    
    public static Box createContactItemBox(ContactItem item){
        Box b = Box.createHorizontalBox();
        item.setAlignmentX(Component.LEFT_ALIGNMENT);
        b.add(item);
        b.setBackground(Color.GREEN);
        b.revalidate();
        b.repaint();
        return b;
    }
    
}
