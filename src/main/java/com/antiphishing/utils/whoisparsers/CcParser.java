package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/17.
 */
/**
 * Domain Name: TEST.CC
 Registry Domain ID: 87231103_DOMAIN_CC-VRSN
 Registrar WHOIS Server: whois.enom.com
 Registrar URL: http://www.enom.com
 Updated Date: 2017-10-14T08:59:34Z
 Creation Date: 1997-10-12T07:00:00Z
 Registry Expiry Date: 2018-10-13T07:00:00Z
 Registrar: ENOM, INC.
 Registrar IANA ID: 48
 Registrar Abuse Contact Email:
 Registrar Abuse Contact Phone:
 Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
 Name Server: DNS1.NAME-SERVICES.COM
 Name Server: DNS2.NAME-SERVICES.COM
 Name Server: DNS3.NAME-SERVICES.COM
 Name Server: DNS4.NAME-SERVICES.COM
 Name Server: DNS5.NAME-SERVICES.COM
 DNSSEC: unsigned
 URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
 >>> Last update of WHOIS database: 2017-11-17T08:14:49Z <<<

 For more information on Whois status codes, please visit https://icann.org/epp

 NOTICE: The expiration date displayed in this record is the date the
 registrar's sponsorship of the domain name registration in the registry is
 currently set to expire. This date does not necessarily reflect the
 expiration date of the domain name registrant's agreement with the
 sponsoring registrar.  Users may consult the sponsoring registrar's
 Whois database to view the registrar's reported date of expiration
 for this registration.

 TERMS OF USE: You are not authorized to access or query our Whois
 database through the use of electronic processes that are high-volume and
 automated except as reasonably necessary to register domain names or
 modify existing registrations; the Data in VeriSign's ("VeriSign") Whois
 database is provided by VeriSign for information purposes only, and to
 assist persons in obtaining information about or related to a domain name
 registration record. VeriSign does not guarantee its accuracy.
 By submitting a Whois query, you agree to abide by the following terms of
 use: You agree that you may use this Data only for lawful purposes and that
 under no circumstances will you use this Data to: (1) allow, enable, or
 otherwise support the transmission of mass unsolicited, commercial
 advertising or solicitations via e-mail, telephone, or facsimile; or
 (2) enable high volume, automated, electronic processes that apply to
 VeriSign (or its computer systems). The compilation, repackaging,
 dissemination or other use of this Data is expressly prohibited without
 the prior written consent of VeriSign. You agree not to use electronic
 processes that are automated and high-volume to access or query the
 Whois database except as reasonably necessary to register domain names
 or modify existing registrations. VeriSign reserves the right to restrict
 your access to the Whois database in its sole discretion to ensure
 operational stability.  VeriSign may restrict or terminate your access to the
 Whois database for failure to abide by these terms of use. VeriSign
 reserves the right to modify these terms at any time.
 */
public class CcParser extends AParser{
    private CcParser(){}

    private static CcParser instance = null;

    public static CcParser getInstance(){
        if(instance == null){
            instance = new CcParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Creation Date:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Updated Date:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
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
