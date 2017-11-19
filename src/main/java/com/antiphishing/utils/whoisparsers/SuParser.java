package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/14.
 */

/**
 * domain:        AAA.SU
 descr:         Magazin SU domains
 descr:         Welcome and Buy domains
 descr:         http://www.aaa.su/
 nserver:       ns1.e-spy.net.
 nserver:       ns4-cloud.nic.ru.
 nserver:       ns4-l2.nic.ru.
 nserver:       ns8-cloud.nic.ru.
 nserver:       ns8-l2.nic.ru.
 state:         REGISTERED, DELEGATED
 person:        Private Person
 e-mail:        law@privacyprotect.info
 registrar:     R01-SU
 created:       2008-08-11T20:00:00Z
 paid-till:     2018-08-11T21:00:00Z
 free-date:     2018-09-14
 source:        TCI

 Last updated on 2017-11-14T10:26:33Z
 */
public class SuParser extends AParser{
    private SuParser(){}
    private static SuParser instance = null;

    public static SuParser getInstance(){
        if(instance == null){
            instance = new SuParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*domain:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\sregistrar:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*created:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Last updated on \\s*[^\\n]+";
    private final String EMAILREG = "\\s*e-mail:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime.trim()).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), "Last updated on ");
            whoisModel.setUtime(simpleDateFormat.parse(utime.trim()).getTime());
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String email = getFieldValue(getMatchField(emailPattern, whoisResponse), ":");
            whoisModel.setEmail(email);
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
