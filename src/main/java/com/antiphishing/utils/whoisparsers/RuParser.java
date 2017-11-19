package com.antiphishing.utils.whoisparsers;

import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;

/**
 * Created by dell on 17-11-19.
 */

/**
 * % By submitting a query to RIPN's Whois Service
 % you agree to abide by the following terms of use:
 % http://www.ripn.net/about/servpol.html#3.2 (in Russian)
 % http://www.ripn.net/about/en/servpol.html#3.2 (in English).

 domain:        YANDEX.RU
 nserver:       ns1.yandex.ru. 213.180.193.1, 2a02:6b8::1
 nserver:       ns2.yandex.ru. 93.158.134.1, 2a02:6b8:0:1::1
 nserver:       ns9.z5h64q92x9.net.
 state:         REGISTERED, DELEGATED, VERIFIED
 org:           YANDEX, LLC.
 registrar:     RU-CENTER-RU
 admin-contact: https://www.nic.ru/whois
 created:       1997-09-23T09:45:07Z
 paid-till:     2018-09-30T21:00:00Z
 free-date:     2018-11-01
 source:        TCI

 Last updated on 2017-11-19T08:31:31Z
 */
public class RuParser extends AParser{
    private RuParser(){}

    private static RuParser instance = null;

    public static RuParser getInstance(){
        if(instance == null){
            instance = new RuParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*domain:\\s*[^\\n]+";
    private final String ORGREG = "\\s*org:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*created:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Last updated on\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern orgPattern = Pattern.compile(ORGREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String org = getFieldValue(getMatchField(orgPattern, whoisResponse), ":");
            whoisModel.setOrgnization(org);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            String utime = getMatchField(utimePattern, whoisResponse).replace("Last updated on","").trim();
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
