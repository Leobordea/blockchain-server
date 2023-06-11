package ui.customcomponents;

import java.time.*;
import java.time.format.DateTimeFormatter;

public class test {
    // main
    public static void main(String[] args) {
    
        Instant instant = Instant.ofEpochMilli(1656153805000l);
        LocalDateTime datetime = LocalDateTime.ofInstant(instant, ZoneId.systemDefault());

        System.out.println(datetime.format(DateTimeFormatter.ofPattern("HH:mm")));
    } 
}
