package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/17.
 */
/**
 * Domain Name: atlasgroup.com.tw
 Registrant:
 聯宙企業有限公司
 Atlas Equipment Corp.
 22F., No 1, Pao Sheng Road, Yuan Ho City, Taipei Hsien, Twiwan, R.O.C.

 Contact:
 Jenny Liu   lily@atlasgroup.com.tw
 TEL:  (02)22320556
 FAX:  (02)22316657

 Record expires on 2019-08-01 (YYYY-MM-DD)
 Record created on 2001-07-31 (YYYY-MM-DD)

 Domain servers in listed order:
 admns1.hinet.net       168.95.192.11
 admns2.hinet.net       168.95.1.11

 Registration Service Provider: HINET
 */
public class TwParser extends AParser{
    private TwParser(){}

    private static TwParser instance = null;

    public static TwParser getInstance(){
        if(instance == null){
            instance = new TwParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String CONCTACTSREG = "\\s*Contact:\\n\\s*[^\\n]+";
    private final String ORGREG = "\\s*Registrant:\\n\\s*[^\\n]+";
    private final String PHONEREG = "\\s*TEL:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Record created on \\s*[^\\(]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactsPattern = Pattern.compile(CONCTACTSREG);
    private Pattern orgPattern = Pattern.compile(ORGREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String contacts = getFieldValue(getMatchField(contactsPattern, whoisResponse), ":");
            String[] items = contacts.split("   ");
            if(items.length > 0){
                whoisModel.setContacts(items[0]);
            }
            if(items.length > 1){
                whoisModel.setEmail(items[1]);
            }
            String org = getFieldValue(getMatchField(orgPattern, whoisResponse), ":");
            whoisModel.setOrgnization(org);
            String phone = getFieldValue(getMatchField(phonePattern, whoisResponse), ":");
            whoisModel.setPhone(phone);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), "on ");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
