package ui.customcomponents;

import javax.swing.Box;
import javax.swing.BoxLayout;
import java.awt.Component;
import java.awt.Color;

public class ChatLayout{
    
    public static Box createChatItemBox(AFChatItem item){
        Box b = Box.createHorizontalBox();
        if (item.isMine){
            item.setAlignmentX(Component.RIGHT_ALIGNMENT);
            b.add(Box.createHorizontalGlue());
            b.add(item);
        }
        else{
            item.setAlignmentX(Component.LEFT_ALIGNMENT);
            b.add(item);
            b.add(Box.createHorizontalGlue());
        }
        b.setBackground(Color.GREEN);
        b.revalidate();
        b.repaint();
        return b;
    }
    
}
