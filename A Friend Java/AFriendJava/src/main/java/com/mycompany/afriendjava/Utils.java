package com.mycompany.afriendjava;

import javax.swing.JFrame;
import java.awt.Window;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/*
* A controller class with various useful utilities
 */
public final class Utils
{

    /** Alerter object used for alerts on windows */
    static WindowAlerter alerter;

    /** Force a window to flash if not focused */
    public static void AlertOnWindow(JFrame frm)
    {
        try
        {
            if (alerter == null)
            {
                alerter = new WindowAlerter();
            }
            alerter.flash(frm);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    static class WindowAlerter
    {
        java.awt.Dialog d;
        
        WindowAlerter()
        {
            
        }

        /** It flashes the window's taskbar icon if the window is not focused. 
         * <br/> The flashing "stops" when the window becomes focused.
         **/
        public void flash(final Window w)
        {
            d = new java.awt.Dialog(w);
            d.setUndecorated(true);
            d.setSize(0, 0);
            d.setModal(false);
            
            d.addWindowFocusListener(new WindowAdapter()
            {

                @Override
                public void windowGainedFocus(WindowEvent e)
                {
                    w.requestFocus();
                    d.setVisible(false);
                    super.windowGainedFocus(e);
                    //w.removeWindowFocusListener(w.getWindowFocusListeners()[0]);
                    //d.removeWindowFocusListener(d.getWindowFocusListeners()[0]);
                }
            });
            w.addWindowFocusListener(new WindowAdapter()
            {

                @Override
                public void windowGainedFocus(WindowEvent e)
                {
                    d.setVisible(false);
                    super.windowGainedFocus(e);
                    //w.removeWindowFocusListener(w.getWindowFocusListeners()[0]);
                    //d.removeWindowFocusListener(d.getWindowFocusListeners()[0]);
                }
            });
            
            if (!w.isFocused())
            {
                //if (d.isVisible())
                {
                    d.setVisible(false);
                }
                d.setLocation(0, 0);
                d.setLocationRelativeTo(w);
                d.setVisible(true);
            }
        }
    }
}