package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/15.
 */
/**
 * Domain Name: PCWORK.INFO
 Registry Domain ID: D45249531-LRMS
 Registrar WHOIS Server: whois.godaddy.com
 Registrar URL: http://www.godaddy.com
 Updated Date: 2017-01-21T14:43:04Z
 Creation Date: 2012-02-03T10:22:40Z
 Registry Expiry Date: 2018-02-03T10:22:40Z
 Registrar Registration Expiration Date:
 Registrar: GoDaddy.com, LLC
 Registrar IANA ID: 146
 Registrar Abuse Contact Email: abuse@godaddy.com
 Registrar Abuse Contact Phone: +1.4806242505
 Reseller:
 Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
 Domain Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited
 Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
 Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
 Registry Registrant ID: C122121881-LRMS
 Registrant Name: LeiLei Liu
 Registrant Organization: PCWORK
 Registrant Street: #68 Jin Dun Street, Qing Yang District
 Registrant City: Chengdu
 Registrant State/Province: Sichuan
 Registrant Postal Code: 610000
 Registrant Country: CN
 Registrant Phone: +86.15984756315
 Registrant Phone Ext:
 Registrant Fax:
 Registrant Fax Ext:
 Registrant Email: support@pcwork.info
 Registry Admin ID: C122121886-LRMS
 Admin Name: LeiLei Liu
 Admin Organization: PCWORK
 Admin Street: #68 Jin Dun Street, Qing Yang District
 Admin City: Chengdu
 Admin State/Province: Sichuan
 Admin Postal Code: 610000
 Admin Country: CN
 Admin Phone: +86.15984756315
 Admin Phone Ext:
 Admin Fax:
 Admin Fax Ext:
 Admin Email: support@pcwork.info
 Registry Tech ID: C122121883-LRMS
 Tech Name: LeiLei Liu
 Tech Organization: PCWORK
 Tech Street: #68 Jin Dun Street, Qing Yang District
 Tech City: Chengdu
 Tech State/Province: Sichuan
 Tech Postal Code: 610000
 Tech Country: CN
 Tech Phone: +86.15984756315
 Tech Phone Ext:
 Tech Fax:
 Tech Fax Ext:
 Tech Email: support@pcwork.info
 Registry Billing ID: C122121889-LRMS
 Billing Name: LeiLei Liu
 Billing Organization: PCWORK
 Billing Street: #68 Jin Dun Street, Qing Yang District
 Billing City: Chengdu
 Billing State/Province: Sichuan
 Billing Postal Code: 610000
 Billing Country: CN
 Billing Phone: +86.15984756315
 Billing Phone Ext:
 Billing Fax:
 Billing Fax Ext:
 Billing Email: support@pcwork.info
 Name Server: F1G1NS2.DNSPOD.NET
 Name Server: F1G1NS1.DNSPOD.NET
 DNSSEC: unsigned
 URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
 >>> Last update of WHOIS database: 2017-11-15T02:34:46Z <<<
 */
public class InfoParser extends AParser{
    private InfoParser(){}

    private static InfoParser instance = null;

    public static InfoParser getInstance(){
        if(instance == null){
            instance = new InfoParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String CONTACTREG = "\\s*Registrant Name:\\s*[^\\n]+";
    private final String ORGNIZATIONREG = "\\s*Registrant Organization:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Creation Date:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Updated Date:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*Registrant Email:\\s*[^\\n]+";
    private final String PHONEREG = "\\s*Registrant Phone:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTREG);
    private Pattern orgnizationPattern = Pattern.compile(ORGNIZATIONREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

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
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime.trim()).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime.trim()).getTime());
            String email = getFieldValue(getMatchField(emailPattern, whoisResponse), ":");
            whoisModel.setEmail(email);
            String phone = getFieldValue(getMatchField(phonePattern, whoisResponse), ":");
            whoisModel.setPhone(phone);
        }catch (Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
