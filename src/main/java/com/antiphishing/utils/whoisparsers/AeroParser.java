package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/17.
 */
/**
 * Domain Name: SITA.AERO
 Registry Domain ID: D104-AERO
 Registrar WHOIS Server:
 Registrar URL:
 Updated Date: 2016-01-29T14:07:47Z
 Creation Date: 2002-03-08T10:44:48Z
 Registry Expiry Date: 2025-03-08T10:44:48Z
 Registrar Registration Expiration Date:
 Registrar: SITA
 Registrar IANA ID: 9999
 Registrar Abuse Contact Email:
 Registrar Abuse Contact Phone:
 Reseller:
 Domain Status: ok https://icann.org/epp#ok
 Registry Registrant ID: C4100788-AERO
 Registrant Name: SITA
 Registrant Organization: Societe Internationale de Telecommunications Aeronautiques
 Registrant Street: Chemin de Joinville 26
 Registrant City: Geneva
 Registrant State/Province:
 Registrant Postal Code: 1216
 Registrant Country: CH
 Registrant Phone: +41.227476000
 Registrant Phone Ext:
 Registrant Fax:
 Registrant Fax Ext:
 Registrant Email: noc@sita.aero
 Registry Admin ID: C4100788-AERO
 Admin Name: SITA
 Admin Organization: Societe Internationale de Telecommunications Aeronautiques
 Admin Street: Chemin de Joinville 26
 Admin City: Geneva
 Admin State/Province:
 Admin Postal Code: 1216
 Admin Country: CH
 Admin Phone: +41.227476000
 Admin Phone Ext:
 Admin Fax:
 Admin Fax Ext:
 Admin Email: noc@sita.aero
 Registry Tech ID: C4100788-AERO
 Tech Name: SITA
 Tech Organization: Societe Internationale de Telecommunications Aeronautiques
 Tech Street: Chemin de Joinville 26
 Tech City: Geneva
 Tech State/Province:
 Tech Postal Code: 1216
 Tech Country: CH
 Tech Phone: +41.227476000
 Tech Phone Ext:
 Tech Fax:
 Tech Fax Ext:
 Tech Email: noc@sita.aero
 Registry Billing ID: C4100788-AERO
 Billing Name: SITA
 Billing Organization: Societe Internationale de Telecommunications Aeronautiques
 Billing Street: Chemin de Joinville 26
 Billing City: Geneva
 Billing State/Province:
 Billing Postal Code: 1216
 Billing Country: CH
 Billing Phone: +41.227476000
 Billing Phone Ext:
 Billing Fax:
 Billing Fax Ext:
 Billing Email: noc@sita.aero
 Name Server: DNS1.EQUANT.NET
 Name Server: DNS2.EQUANT.NET
 Name Server: DNS3.EQUANT.NET
 DNSSEC: unsigned
 ENS_AuthId: E00001-SITA
 URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
 >>> Last update of WHOIS database: 2017-11-17T01:37:13Z <<<

 For more information on Whois status codes, please visit https://icann.org/epp
 */
public class AeroParser extends AParser{
    private AeroParser(){}

    private static AeroParser instance = null;

    public static AeroParser getInstance(){
        if(instance == null){
            instance = new AeroParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*Registrant Name:\\s*[^\\n]+";
    private final String ORGREG = "\\s*Registrant Organization:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Creation Date:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Updated Date:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*Registrant Email:\\s*[^\\n]+";
    private final String PHONEREG = "\\s*Registrant Phone:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);
    private Pattern orgPattern = Pattern.compile(ORGREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String org = getFieldValue(getMatchField(orgPattern, whoisResponse), ":");
            whoisModel.setOrgnization(org);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
            String email = getFieldValue(getMatchField(emailPattern, whoisResponse), ":");
            whoisModel.setEmail(email);
            String phone = getFieldValue(getMatchField(phonePattern, whoisResponse), ":");
            whoisModel.setPhone(phone);
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
