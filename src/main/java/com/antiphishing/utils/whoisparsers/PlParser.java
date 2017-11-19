package com.antiphishing.utils.whoisparsers;

import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;

/**
 * Created by dell on 17-11-18.
 */

/**
 * DOMAIN NAME:           universalmusic.pl
 registrant type:       organization
 nameservers:           dns6.epox.pl.
 dns7.epox.pl.
 created:               1999.04.20 13:00:00
 last modified:         2017.04.21 11:11:43
 renewal date:          2018.04.19 14:00:00

 no option

 dnssec:                Unsigned


 REGISTRAR:
 home.pl S.A.
 ul. Zbożowa 4
 70-653 Szczecin
 Polska/Poland
 +48.914325555
 +48.504502500
 https://home.pl/kontakt
 */
public class PlParser extends AParser{
    private PlParser(){}

    private static PlParser instance = null;

    public static PlParser getInstance(){
        if(instance == null){
            instance = new PlParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*DOMAIN NAME:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*created:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*last modified:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss");

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
