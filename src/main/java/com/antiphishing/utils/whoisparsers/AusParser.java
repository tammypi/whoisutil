package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.util.regex.Pattern;
/**
 * Created by dell on 17-11-19.
 */

/**
 * Domain Name:                     vodafone.com.au
 Last Modified:                   25-May-2017 04:43:53 UTC
 Status:                          ok
 Registrar Name:                  NetNames

 Registrant:                      Vodafone Group PLC
 Eligibility Type:                Trademark Owner
 Eligibility Name:                VODAFONE
 Eligibility ID:                  TM 1104633

 Registrant Contact ID:           C6148087-EX
 Registrant Contact Name:         Ravi Mohindra
 Registrant Contact Email:        Visit whois.ausregistry.com.au for Web based WhoIs

 Tech Contact ID:                 AT1681623438171
 Tech Contact Name:               NetNames Hostmaster
 Tech Contact Email:              Visit whois.ausregistry.com.au for Web based WhoIs

 Name Server:                     vfaudns01.vodafone.com.au
 Name Server IP:                  202.81.67.132
 Name Server:                     vfaudns02.vodafone.com.au
 Name Server IP:                  202.81.67.4
 Name Server:                     ns1.vodafone.com.au
 Name Server:                     ns2.vodafone.com.au
 DNSSEC:                          signedDelegation
 */
public class AusParser extends AParser{
    private AusParser(){}

    private static AusParser instance = null;

    public static AusParser getInstance(){
        if(instance == null){
            instance = new AusParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String CONTACTSNAME = "\\s*Registrant Contact Name:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSNAME);

    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String contact = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contact);
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
