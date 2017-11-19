package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/17.
 */
/**
 * Domain Name: about.museum
 Registry Domain ID: DOM000000000677-MUSEUM
 Registrar URL:
 Updated Date: 2017-11-13T10:06:09Z
 Creation Date: 2005-02-04T18:32:48Z
 Registry Expiry Date: 2019-02-04T19:32:48Z
 Registrar: Registry Operations
 Registrar IANA ID: 9999
 Registrar Abuse Contact Email:
 Registrar Abuse Contact Phone:
 Domain Status: ok  https://icann.org/epp#ok
 Domain Status: transferPeriod  https://icann.org/epp#transferPeriod
 Registry Registrant ID: MC104-MUSEUM
 Registrant Name: Marie Claverie
 Registrant Street: 1, rue miollis
 Registrant City: Paris
 Registrant Postal Code: 75015
 Registrant Country: FR
 Registrant Phone: +33.147340500
 Registrant Email: info@icom.museum
 Registry Admin ID: SB105-MUSEUM
 Admin Name: Sonntag Benjamin
 Admin Street: 29, rue merlin
 Admin City: Paris
 Admin State/Province: IDF
 Admin Postal Code: 75011
 Admin Country: FR
 Admin Phone: +33.950568088
 Admin Email: museum@octopuce.fr
 Registry Tech ID: SB105-MUSEUM
 Tech Name: Sonntag Benjamin
 Tech Street: 29, rue merlin
 Tech City: Paris
 Tech State/Province: IDF
 Tech Postal Code: 75011
 Tech Country: FR
 Tech Phone: +33.950568088
 Tech Email: museum@octopuce.fr
 Name Server: primary.heberge.info
 Name Server: secondary.heberge.info
 DNSSEC: unsigned
 URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
 >>> Last update of WHOIS database: 2017-11-17T03:08:43Z <<<

 For more information on Whois status codes, please visit https://icann.org/epp

 Rights restricted by copyright.
 Terms of Use : MuseDoma's database is protected by the provisions of the French Law of the 1st of July 1998
 transposing the European Directive of the 11th of March 1996 on database legal protection in the Intellectual Property Code.

 MuseDoma is the only entity to hold the producing rights of the databases as substantial investment, quantitative
 as much as qualitative, that were used to achieve this database.
 Complete or partial reproduction and/or use of MuseDoma's database without the express permission of MuseDoma's is strictly forbidden.

 Any breach to these rules can carry penal sanctions as counterfeit, without prejudice of a potential damages request from MuseDoma,
 holder of these rights. MuseDoma's database user commits to use the published data according to the laws
 and rules in effect. Moreover, the user is bound to respect the French Data Protection Law.
 The infringement of the French Data Protection Law can carry penal sanctions. As the user will access personal information,
 the user must refrain from collecting or misuse this information. In a more general way, the user must refrain from any act likely
 to infringe the privacy or reputation of individuals.
 */
public class MuseumParser extends AParser{
    private MuseumParser(){}

    private static MuseumParser instance = null;

    public static MuseumParser getInstance(){
        if(instance == null){
            instance = new MuseumParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*Registrant Name:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Creation Date:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Updated Date:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*Registrant Email:\\s*[^\\n]+";
    private final String PHONERGE = "\\s*Registrant Phone:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private Pattern phonePattern = Pattern.compile(PHONERGE);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime.trim()).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime.trim()).getTime());
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
