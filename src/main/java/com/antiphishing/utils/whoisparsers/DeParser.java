package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/17.
 */
/**
 * Domain: dehua.de
 Status: connect
 */
public class DeParser extends AParser{
    private DeParser(){}

    public static DeParser instance = null;

    public static DeParser getInstance(){
        if(instance == null){
            instance = new DeParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
