package com.antiphishing.utils.whoisparsers;

import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Created by dell on 2017/11/15.
 */
/**
 Access to .IN WHOIS information is provided to assist persons in determining the contents of a domain name registration record in the .IN registry database. The data in this record is provided by .IN Registry for informational purposes only, and .IN does not guarantee its accuracy.  This service is intended only for query-based access. You agree that you will use this data only for lawful purposes and that, under no circumstances will you use this data to: (a) allow, enable, or otherwise support the transmission by e-mail, telephone, or facsimile of mass unsolicited, commercial advertising or solicitations to entities other than the data recipient's own existing customers; or (b) enable high volume, automated, electronic processes that send queries or data to the systems of Registry Operator, a Registrar, or Afilias except as reasonably necessary to register domain names or modify existing registrations. All rights reserved. .IN reserves the right to modify these terms at any time. By submitting this query, you agree to abide by this policy.

 Domain ID:D581989-AFIN
 Domain Name:TEST.IN
 Created On:17-Feb-2005 05:29:08 UTC
 Last Updated On:16-Feb-2016 13:02:04 UTC
 Expiration Date:17-Feb-2021 05:29:08 UTC
 Sponsoring Registrar:Endurance Domains Technology LLP (R173-AFIN)
 Status:CLIENT TRANSFER PROHIBITED
 Reason:
 Registrant ID:WIQ_28116392
 Registrant Name:Domain Manager
 Registrant Organization:Online Directory Services
 Registrant Street1:Office C-119, Grace Plaza,
 Registrant Street2:S. V. Road,
 Registrant Street3:Jogeshwari
 Registrant City:Mumbai
 Registrant State/Province:Maharashtra
 Registrant Postal Code:400102
 Registrant Country:IN
 Registrant Phone:+91.9167338231
 Registrant Phone Ext.:
 Registrant FAX:
 Registrant FAX Ext.:
 Registrant Email:info@onlinedirectoryservices.org
 Admin ID:WIQ_28116392
 Admin Name:Domain Manager
 Admin Organization:Online Directory Services
 Admin Street1:Office C-119, Grace Plaza,
 Admin Street2:S. V. Road,
 Admin Street3:Jogeshwari
 Admin City:Mumbai
 Admin State/Province:Maharashtra
 Admin Postal Code:400102
 Admin Country:IN
 Admin Phone:+91.9167338231
 Admin Phone Ext.:
 Admin FAX:
 Admin FAX Ext.:
 Admin Email:info@onlinedirectoryservices.org
 Tech ID:WIQ_28116392
 Tech Name:Domain Manager
 Tech Organization:Online Directory Services
 Tech Street1:Office C-119, Grace Plaza,
 Tech Street2:S. V. Road,
 Tech Street3:Jogeshwari
 Tech City:Mumbai
 Tech State/Province:Maharashtra
 Tech Postal Code:400102
 Tech Country:IN
 Tech Phone:+91.9167338231
 Tech Phone Ext.:
 Tech FAX:
 Tech FAX Ext.:
 Tech Email:info@onlinedirectoryservices.org
 Name Server:NS1.ONLINEDIRECTORYSERVICES.ORG
 Name Server:NS2.ONLINEDIRECTORYSERVICES.ORG
 Name Server:
 Name Server:
 Name Server:
 Name Server:
 Name Server:
 Name Server:
 Name Server:
 Name Server:
 Name Server:
 Name Server:
 Name Server:
 DNSSEC:Unsigned
 */
public class InParser extends AParser{
    private InParser(){}

    private static InParser instance = null;

    public static InParser getInstance(){
        if(instance == null){
            instance = new InParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*Registrant Name:\\s*[^\\n]+";
    private final String ORGNIZATIONREG = "\\s*Registrant Organization:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Created On:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Last Updated On:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*Registrant Email:\\s*[^\\n]+";
    private final String PHONEREG = "\\s*Registrant Phone:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);
    private Pattern orgnizationPattern = Pattern.compile(ORGNIZATIONREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private Pattern emailattern = Pattern.compile(EMAILREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd-MMM-yyyy HH:mm:ss", Locale.ENGLISH);

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String orgnization = getFieldValue(getMatchField(orgnizationPattern, whoisResponse), ":");
            whoisModel.setOrgnization(orgnization);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime.trim()).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime.trim()).getTime());
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String email = getFieldValue(getMatchField(emailattern, whoisResponse), ":");
            whoisModel.setEmail(email);
            String phone = getFieldValue(getMatchField(phonePattern, whoisResponse), ":");
            whoisModel.setPhone(phone);
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
