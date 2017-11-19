package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/17.
 */
/**
 * Estonia .ee Top Level Domain WHOIS server

 Domain:
 name:       test.ee
 status:     ok (paid and in zone)
 registered: 2016-02-18 12:56:50 +02:00
 changed:    2017-02-01 13:40:03 +02:00
 expire:     2018-02-19
 outzone:
 delete:

 Registrant:
 name:    OÜ Computernik
 org id:  10968990
 country: EE
 email:   Not Disclosed - Visit www.internet.ee for webbased WHOIS
 changed: 2016-02-18 12:56:50 +02:00

 Administrative contact:
 name:       Günther Veidenberg
 email:      Not Disclosed - Visit www.internet.ee for webbased WHOIS
 changed:    2016-02-18 12:56:50 +02:00


 Technical contact:
 name:       Günther Veidenberg
 email:      Not Disclosed - Visit www.internet.ee for webbased WHOIS
 changed:    2016-02-18 12:56:50 +02:00

 Registrar:
 name:       ALMIC OÜ
 url:        http://www.almic.ee
 phone:      +372 6461078
 changed:    2015-11-30 23:29:03 +02:00

 Name servers:
 nserver:   ns2.sedoparking.com
 nserver:   ns1.sedoparking.com
 changed:   2016-02-18 12:56:50 +02:00

 Estonia .ee Top Level Domain WHOIS server
 More information at http://internet.ee
 */
public class EeParser extends AParser{
    private EeParser(){}

    private static EeParser instance = null;

    public static EeParser getInstance(){
        if(instance == null){
            instance = new EeParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain:\\nname:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*Registrant:\\nname:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*registered:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*changed:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactsPattern = Pattern.compile(CONTACTSREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss X");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":").replaceAll("\\s+","").replaceAll("name:","");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String contacts = getFieldValue(getMatchField(contactsPattern, whoisResponse), ":").replaceAll("name:","").trim();
            whoisModel.setContacts(contacts);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
