package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/17.
 */

/**
 Domain Name:                     australia.gov.au
 Last Modified:                   22-Dec-2016 06:20:06 UTC
 Status:                          clientDeleteProhibited
 Status:                          clientUpdateProhibited
 Registrar Name:                  Digital Transformation Agency

 Registrant:                      Digital Transformation Agency (DTA)
 Eligibility Type:                Other

 Registrant Contact ID:           GOVAU-IVLY1033
 Registrant Contact Name:         Tobias Wright
 Registrant Contact Email:        Visit whois.ausregistry.com.au for Web based WhoIs

 Tech Contact ID:                 GOVAU-SUTE1002
 Tech Contact Name:               Technical Support
 Tech Contact Email:              Visit whois.ausregistry.com.au for Web based WhoIs

 Name Server:                     ns-180.awsdns-22.com
 Name Server:                     ns-780.awsdns-33.net
 Name Server:                     ns-1789.awsdns-31.co.uk
 Name Server:                     ns-1416.awsdns-49.org
 DNSSEC:                          unsigned
 */
public class AuParser extends AParser{
    private AuParser(){}

    private static AuParser instance = null;

    public static AuParser getInstance(){
        if(instance == null){
            instance = new AuParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*Registrant Contact Name:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Last Modified:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactsPattern = Pattern.compile(CONTACTSREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd-MMM-yyyy HH:mm:ss 'UTC'", Locale.ENGLISH);

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String contacts = getFieldValue(getMatchField(contactsPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
