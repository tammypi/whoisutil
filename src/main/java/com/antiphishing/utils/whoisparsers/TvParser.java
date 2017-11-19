package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/17.
 */
/**
 * Server Name: TEST.TV
 IP Address: 95.211.156.247
 Registrar: DYNADOT, LLC
 Registrar WHOIS Server: whois.dynadot.com
 Registrar URL: http://www.dynadot.com

 Domain Name: TEST.TV
 Registry Domain ID: 92027549_DOMAIN_TV-VRSN
 Registrar WHOIS Server: whois.dynadot.com
 Registrar URL: http://www.dynadot.com
 Updated Date: 2017-11-09T14:43:37Z
 Creation Date: 2010-03-18T17:16:19Z
 Registry Expiry Date: 2018-03-18T17:16:19Z
 Registrar: DYNADOT, LLC
 Registrar IANA ID: 472
 Registrar Abuse Contact Email: abuse@dynadot.com
 Registrar Abuse Contact Phone: +16502620100
 Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
 Name Server: NS1.TIMEWEB.RU
 Name Server: NS2.TIMEWEB.RU
 Name Server: NS3.TIMEWEB.ORG
 DNSSEC: unsigned
 URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
 >>> Last update of WHOIS database: 2017-11-17T03:50:04Z <<<

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
public class TvParser extends AParser{
    private TvParser(){}

    private static TvParser instance = null;

    public static TvParser getInstance(){
        if(instance == null){
            instance = new TvParser();
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
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
