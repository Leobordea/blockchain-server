package com.mycompany.afriendjava;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.sql.Timestamp;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.UIManager;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class Program {

    public static ExecutorService executor = Executors.newCachedThreadPool();
    public static MainUI mainform;
    public static int[] thisversion = {3, 2, 1, 2};
    public static Gson gson = new GsonBuilder().registerTypeAdapter(Timestamp.class, new TimestampAdapter()).create();
    public static void main(String[] args) {
        try{
            boolean newv = false;
            try{
                URL url = new URL("http://mancitiss.duckdns.org/index.htm");
                String data = null;
                try(BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()))){
                   data = reader.readLine();
                }
                System.out.println(data);
                String[] newestversion = data.split("\\.");
                int[] newestversionint = new int[newestversion.length];
                for(int i = 0; i < newestversion.length; i++){
                    newestversionint[i] = Integer.parseInt(newestversion[i]);
                }
                System.out.println("This version: " + thisversion[0] + "." + thisversion[1] + "." + thisversion[2] + "." + thisversion[3]);
                System.out.println("Newest version: " + newestversionint[0] + "." + newestversionint[1] + "." + newestversionint[2] + "." + newestversionint[3]);
                for(int i = 0; i < thisversion.length; i++){
                    if (i>=4) break;
                    if(thisversion[i] < newestversionint[i]){
                        newv = true;
                        break;
                    }
                    else if (newestversionint[i] == thisversion[i]){
                        continue;
                    }
                    else break;
                }
            }
            catch(Exception e){
                e.printStackTrace();
            }
            if (newv){
                java.awt.EventQueue.invokeLater(() -> {
                    new Login().setVisible(true);
                });
            } else {
                java.awt.EventQueue.invokeLater(() -> {
                    new Login().setVisible(true);
                });
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}
