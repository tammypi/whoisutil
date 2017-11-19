package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/15.
 */

/**
 * % DOTGOV WHOIS Server ready
 Domain Name: KANSAS.GOV
 Status: ACTIVE

 >>> Last update of whois database: 2017-11-15T06:09:05Z <<<
 Please be advised that this whois server only contains information pertaining
 to the .GOV domain. For information for other domains please use the whois
 server at RS.INTERNIC.NET.
 */
public class GovParser extends AParser{
    private GovParser(){}

    private static GovParser instance = null;

    public static GovParser getInstance(){
        if(instance == null){
            instance = new GovParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*>>> Last update of whois database: \\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
