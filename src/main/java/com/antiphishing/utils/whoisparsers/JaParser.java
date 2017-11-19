package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/16.
 */
/**
 * Domain:
 cardiff.ac.uk

 Registered For:
 Cardiff University

 Domain Owner:
 Cardiff University

 Registered By:
 Jisc Services Limited

 Servers:
 ns0.cf.ac.uk	131.251.133.10
 ns1.cf.ac.uk
 ns3.ja.net

 Registrant Contact:
 Robert Dew

 Registrant Address:
 Information Services
 Cardiff University
 40-41 Park Place
 Cardiff
 South Glamorgan
 CF10 3BB
 United Kingdom
 +44 29 2087 4875 (Phone)
 +44 29 2087 4285 (FAX)
 hostmaster@Cardiff.ac.uk

 Renewal date:
 Tuesday 29th Oct 2019

 Entry updated:
 Saturday 29th July 2017

 Entry created:
 Friday 7th November 2003
 */
public class JaParser extends AParser{
    private JaParser(){}

    private static JaParser instance = null;

    public static JaParser getInstance(){
        if(instance == null){
            instance = new JaParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain:\\n\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*Registered For:\\n\\s*[^\\n]+";
    private final String ORGNIZATIONREG = "\\s*Registered By:\\n\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Entry created:\\n\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Entry updated:\\n\\s*[^\\n]+";
    private final String PHONEREG = "\\s*\\+[^\\(]+\\s\\(Phone\\)";
    private final String EMAILREG = "\\w+(\\.\\w)*@\\w+(\\.\\w{2,3}){1,3}";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);
    private Pattern orgnizationPattern = Pattern.compile(ORGNIZATIONREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE dd'th' MMM yyyy", Locale.ENGLISH);

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String orgnization = getFieldValue(getMatchField(orgnizationPattern, whoisResponse), ":");
            whoisModel.setOrgnization(orgnization);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
            String phone = getMatchField(phonePattern, whoisResponse);
            whoisModel.setPhone(phone.trim().replace("(Phone)", ""));
            String email = getMatchField(emailPattern, whoisResponse);
            whoisModel.setEmail(email);
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
