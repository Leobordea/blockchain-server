package ui.customcomponents;

import javax.swing.AbstractAction;
import javax.swing.Action;

import org.apache.commons.lang3.exception.ExceptionContext;

import java.awt.event.ActionEvent;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.Toolkit;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import com.mycompany.afriendjava.AFriendClient;
import com.mycompany.afriendjava.Tools;

public class PasteAction extends AbstractAction {

    private Action action;
    private String id;

    public PasteAction(Action action, String id) {
        this.action = action;
        this.id = id;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        action.actionPerformed(e);
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                int numberOfTrials = 0;
                while (numberOfTrials < 2){
                    try{
                        Transferable content = Toolkit.getDefaultToolkit().getSystemClipboard().getContents(null);
                        if (content != null && content.isDataFlavorSupported(DataFlavor.imageFlavor)) {
                            BufferedImage img = (BufferedImage) content.getTransferData(DataFlavor.imageFlavor);
                            String imgString = Tools.ImageToBASE64(img);
                            try{
                                //System.out.println("1902"+id+Tools.data_with_ASCII_byte(imgString));
                                AFriendClient.queueCommand(Tools.combine(("1902" + id).getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(imgString).getBytes(StandardCharsets.US_ASCII)));
                            }
                            catch(Exception ex){
                                ex.printStackTrace();
                            }
                            //System.out.println(imgString);
                        }
                        System.out.println("Paste Occured...");
                        break;
                    }
                    catch (Exception ex){
                        numberOfTrials++;
                        ex.printStackTrace();
                        try {
                            Thread.sleep(20);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        });
        thread.start();
    }

}