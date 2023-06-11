package com.mycompany.afriendjava;

public class WriteCommand {
    public String file;
    public long offset;
    public int received_byte;
    public byte[] databyte;

    public WriteCommand(String file, long offset, int received_byte, byte[] databyte)
    {
        this.file = file;
        this.offset = offset;
        this.received_byte = received_byte;
        this.databyte = databyte;
    }
}
