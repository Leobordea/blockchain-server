package com.mycompany.afriendjava;

public class FileToWrite {
    public long size;
    public java.io.FileInputStream fis;
    public java.io.FileOutputStream fos;

    public FileToWrite(){}

    public FileToWrite(long size, java.io.FileInputStream fis){
        this.size = size;
        this.fis = fis;
    }

    public FileToWrite(long size, java.io.FileOutputStream fos){
        this.size = size;
        this.fos = fos;
    }

    public FileToWrite(long size){
        this.size = size;
    }

}
