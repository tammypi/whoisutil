package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/16.
 */

/**
 * %
 %AM TLD whois server #1
 % Please see 'whois -h whois.amnic.net help' for usage.
 %

 Domain name: test.am
 Registrar:   abcdomain (ABCDomain LLC)
 Status:      active

 Registrant:
 Social Media LLC
 1 Charents street
 Yerevan,  0001
 AM

 Administrative contact:
 Social Media LLC
 1 Charents street
 Yerevan, 0001
 AM
 marketing@mamul.am
 091992202, 552059

 Technical contact:
 Social Media LLC
 1 Charents street
 Yerevan, 0001
 AM
 marketing@mamul.am
 091992202, 552059

 DNS servers:
 ns8.host.am
 ns3.host.am

 Registered:    2013-10-10
 Last modified: 2017-09-26
 Expires:       2018-10-10
 */
public class AmParser extends AParser{
    private AmParser(){}

    private static AmParser instance = null;

    public static AmParser getInstance(){
        if(instance == null){
            instance = new AmParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain name:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*Registrar:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Registered:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Last modified:\\s*[^\\n]+";
    private final String EMAILREG = "\\w+(\\.\\w)*@\\w+(\\.\\w{2,3}){1,3}";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contact = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contact);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
            String email = getMatchField(emailPattern, whoisResponse);
            whoisModel.setEmail(email);
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
