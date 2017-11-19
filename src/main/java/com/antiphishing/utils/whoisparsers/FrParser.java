package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/16.
 */

/**
 * %%
 %% This is the AFNIC Whois server.
 %%
 %% complete date format : DD/MM/YYYY
 %% short date format    : DD/MM
 %% version              : FRNIC-2.5
 %%
 %% Rights restricted by copyright.
 %% See https://www.afnic.fr/en/products-and-services/services/whois/whois-special-notice/
 %%
 %% Use '-h' option to obtain more information about this service.
 %%
 %% [119.97.214.138 REQUEST] >> coe.fr
 %%
 %% RL Net [##########] - RL IP [#########.]
 %%

 domain:      coe.fr
 status:      ACTIVE
 hold:        NO
 holder-c:    ANO00-FRNIC
 admin-c:     OVH5-FRNIC
 tech-c:      OVH5-FRNIC
 zone-c:      NFC1-FRNIC
 nsl-id:      NSL40848-FRNIC
 registrar:   OVH
 Expiry Date: 28/05/2018
 created:     24/08/2006
 last-update: 28/05/2017
 source:      FRNIC

 ns-list:     NSL40848-FRNIC
 nserver:     ns17.ovh.net
 nserver:     dns17.ovh.net
 source:      FRNIC

 registrar:   OVH
 type:        Isp Option 1
 address:     2 Rue Kellermann
 address:     59100 ROUBAIX
 country:     FR
 phone:       +33 8 99 70 17 61
 fax-no:      +33 3 20 20 09 58
 e-mail:      support@ovh.net
 website:     http://www.ovh.com
 anonymous:   NO
 registered:  21/10/1999
 source:      FRNIC

 nic-hdl:     ANO00-FRNIC
 type:        PERSON
 contact:     Ano Nymous
 remarks:     -------------- WARNING --------------
 remarks:     While the registrar knows him/her,
 remarks:     this person chose to restrict access
 remarks:     to his/her personal data. So PLEASE,
 remarks:     don't send emails to Ano Nymous. This
 remarks:     address is bogus and there is no hope
 remarks:     of a reply.
 remarks:     -------------- WARNING --------------
 registrar:   OVH
 changed:     31/12/2014 anonymous@anonymous
 anonymous:   YES
 obsoleted:   NO
 eligstatus:  ok
 eligdate:    31/12/2014 00:33:05
 source:      FRNIC

 nic-hdl:     OVH5-FRNIC
 type:        ROLE
 contact:     OVH NET
 address:     OVH
 address:     140, quai du Sartel
 address:     59100 Roubaix
 country:     FR
 phone:       +33 8 99 70 17 61
 e-mail:      tech@ovh.net
 trouble:     Information: http://www.ovh.fr
 trouble:     Questions:  mailto:tech@ovh.net
 trouble:     Spam: mailto:abuse@ovh.net
 admin-c:     OK217-FRNIC
 tech-c:      OK217-FRNIC
 notify:      tech@ovh.net
 registrar:   OVH
 changed:     11/10/2006 tech@ovh.net
 anonymous:   NO
 obsoleted:   NO
 source:      FRNIC
 */
public class FrParser extends AParser{
    private FrParser(){}

    private static FrParser instance = null;

    public static FrParser getInstance(){
        if(instance == null){
            instance = new FrParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*domain:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*admin\\-c:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*created:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*last\\-update:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*e\\-mail:\\s*[^\\n]+";
    private final String PHONEREG = "\\s*phone:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactsPattern = Pattern.compile(CONTACTSREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd/MM/yyyyy");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactsPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
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
