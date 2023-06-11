package com.mycompany.afriendjava;

import java.io.FileInputStream;
import java.io.FileOutputStream;

public class AFile {
    public String name;
    public long size;
    public FileInputStream fis;
    public FileOutputStream fos;

    public AFile(){}

    public AFile(String name, long size){
        this.name = name;
        this.size = size;
    }
}
