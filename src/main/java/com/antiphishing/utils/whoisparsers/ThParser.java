package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.regex.Pattern;
/**
 * Created by dell on 17-11-18.
 */
/**
 * Whois Server Version 2.1.3

 Domain: RAILWAY.CO.TH
 Registrar: T.H.NIC Co., Ltd.
 Name Server: NS.KSC.CO.TH
 Name Server: NS2.KSC.CO.TH
 Status: ACTIVE
 Updated date: 11 Mar 2016
 Created date: 11 Feb 2003
 Exp date: 10 Feb 2018
 Domain Holder: The State Railway of Thailand ( การรถไฟแห่งประเทศไทย )
 1 Rongmuang Rd., Lumpinee, Pathumwan, Bangkok
 10330
 TH

 Tech Contact: 587187
 บริษัท เคเอสซี คอมเมอร์เชียล อินเตอร์เนต จำกัด
 2/4 อาคารไทยพาณิชย์สามัคคีประกันภัย ชั้น 10 ถนนวิภาวดีรังสิต
 แขวงทุ่งสองห้อง เขตหลักสี่ กรุงเทพฯ
 10210
 TH



 >>> Last update of whois data: Sat, 18 Nov 2017 16:34:20 UTC+7 <<<

 For more information please visit: https://www.thnic.co.th/whois
 */
public class ThParser extends AParser{
    private ThParser(){}

    private static ThParser instance = null;

    public static ThParser getInstance(){
        if(instance == null){
            instance = new ThParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Created date:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Updated date:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd MMM yyyy", Locale.ENGLISH);

    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":").replaceAll("\\s+", "").replaceAll("name:", "");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setCtime((simpleDateFormat).parse(ctime).getTime());
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
