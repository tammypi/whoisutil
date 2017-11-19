package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.regex.Pattern;
/**
 * Created by dell on 17-11-19.
 */

/**
 * --------------------------

 Domain Name: HUSSON.EDU

 Registrant:
 Husson University
 One College Circle
 Bangor, ME 04401
 UNITED STATES

 Administrative Contact:
 Frank Barton
 Husson University
 1 College Circle
 Bangor, ME 04401
 UNITED STATES
 (207) 941-7839
 bartonf@husson.edu

 Technical Contact:
 Joe DiStefano
 Sephone Interactive Media
 PO Box 2357
 Bangor, ME 04402
 UNITED STATES
 (207) 262-5040
 dns_services@sephone.com

 Name Servers:
 NS-1246.AWSDNS-27.ORG
 NS-573.AWSDNS-07.NET
 NS-446.AWSDNS-55.COM
 NS-1678.AWSDNS-17.CO.UK

 Domain record activated:    22-Jan-1993
 Domain record last updated: 27-Apr-2016
 Domain expires:             31-Jul-2018
 */
public class EduParser extends AParser{
    private EduParser(){}

    private static EduParser instance = null;

    public static EduParser getInstance(){
        if(instance == null){
            instance = new EduParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String CONTACTREG = "\\s*Registrant:\\n\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Domain record activated:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Domain record last updated:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd-MMM-yyyy", Locale.ENGLISH);

    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String contact = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contact);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
