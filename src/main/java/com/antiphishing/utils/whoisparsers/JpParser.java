package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;

/**
 * Created by dell on 2017/11/16.
 */

/**
 * [ JPRS database provides information on network administration. Its use is    ]
 [ restricted to network administration purposes. For further information,     ]
 [ use 'whois -h whois.jprs.jp help'. To suppress Japanese output, add'/e'     ]
 [ at the end of command, e.g. 'whois -h whois.jprs.jp xxx/e'.                 ]

 Domain Information: [ドメイン情報]
 [Domain Name]                   AAA.JP

 [登録者名]                      大竹　敏保
 [Registrant]                    Ootake Toshiyasu

 [Name Server]                   ns1.dns.ne.jp
 [Name Server]                   ns2.dns.ne.jp
 [Signing Key]

 [登録年月日]                    2007/02/03
 [有効期限]                      2018/02/28
 [状態]                          Active
 [最終更新]                      2017/08/29 10:56:47 (JST)

 Contact Information: [公開連絡窓口]
 [名前]                          リンククラブWHOIS情報公開代行サービス
 [Name]                          Linkclub Whois Information Protection Service
 [Email]                         support@hosting-link.ne.jp
 [Web Page]
 [郵便番号]
 [住所]
 [Postal Address]
 [電話番号]                      03-5778-3738
 [FAX番号]
 */
public class JpParser extends AParser{
    private JpParser(){}

    private static JpParser instance = null;

    public static JpParser getInstance(){
        if(instance == null){
            instance = new JpParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*\\[Domain Name\\]\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*\\[登録者名\\]\\s*[^\\n]+";
    private final String ORGNIZATIONREG = "\\s*\\[Registrant\\]\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*\\[登録年月日\\]\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*\\[最終更新\\]\\s*[^\\n]+";
    private final String EMAILREG = "\\s*\\[Email\\]\\s*[^\\n]+";
    private final String PHONEREG = "\\s*\\[電話番号\\]\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);
    private Pattern orgnizationPattern = Pattern.compile(ORGNIZATIONREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private Pattern emailattern = Pattern.compile(EMAILREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private SimpleDateFormat simpleDateFormat1 = new SimpleDateFormat("yyyy/MM/dd");
    private SimpleDateFormat simpleDateFormat2 = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss '(JST)'");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), "]");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), "]");
            whoisModel.setContacts(contacts);
            String orgnization = getFieldValue(getMatchField(orgnizationPattern, whoisResponse), "]");
            whoisModel.setOrgnization(orgnization);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), "]");
            whoisModel.setCtime(simpleDateFormat1.parse(ctime.trim()).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), "]");
            whoisModel.setUtime(simpleDateFormat2.parse(utime.trim()).getTime());
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String email = getFieldValue(getMatchField(emailattern, whoisResponse), "]");
            whoisModel.setEmail(email);
            String phone = getFieldValue(getMatchField(phonePattern, whoisResponse), "]");
            whoisModel.setPhone(phone);
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
