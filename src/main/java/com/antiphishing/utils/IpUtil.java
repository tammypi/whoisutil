package com.antiphishing.utils;
import java.io.Serializable;
import java.net.InetAddress;

/**
 * Created by dell on 17-11-19.
 */
public class IpUtil implements Serializable{
    public static String getIpByDomain(String domain){
        String ip = "";
        try{
            InetAddress[] inetAdresses = InetAddress.getAllByName(domain);
            if(inetAdresses != null && inetAdresses.length > 0){
                ip = inetAdresses[0].getHostAddress();
            }
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return ip;
    }
}
