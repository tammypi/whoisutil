package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/17.
 */
/**
 * Domain Name: shou.org.cn
 ROID: 20100709s10051s53120303-cn
 Domain Status: ok
 Registrant ID: hc099798798-cn
 Registrant: 上海电视大学
 Registrant Contact Email: jichenjun@shtvu.edu.cn
 Sponsoring Registrar: 阿里云计算有限公司（万网）
 Name Server: dns13.hichina.com
 Name Server: dns14.hichina.com
 Registration Time: 2010-07-09 14:36:16
 Expiration Time: 2019-07-09 14:36:16
 DNSSEC: unsigned
 */
public class CnParser extends AParser{
    private CnParser(){}

    private static CnParser instance = null;

    public static CnParser getInstance(){
        if(instance == null){
            instance = new CnParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*Registrant:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*Registrant Contact Email:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Registration Time:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactsPattern = Pattern.compile(CONTACTSREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactsPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String email = getFieldValue(getMatchField(emailPattern, whoisResponse), ":");
            whoisModel.setEmail(email);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
