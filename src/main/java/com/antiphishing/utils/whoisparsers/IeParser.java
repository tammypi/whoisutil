package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/16.
 */
/**
 * % Rights restricted by copyright; http://iedr.ie/index.php/mnudomregs/mnudnssearch/96
 % Do not remove this notice

 domain:       test.ie
 descr:        Advanced Packaging Machinery ltd
 descr:        Body Corporate (Ltd,PLC,Company)
 descr:        Corporate Name
 admin-c:      AYB277-IEDR
 tech-c:       ABG704-IEDR
 registration: 21-June-2004
 renewal:      21-June-2018
 holder-type:  Billable
 locked:       NO
 ren-status:   Active
 in-zone:      1
 nserver:      ns9.dnsireland.com
 nserver:      ns10.dnsireland.com
 source:       IEDR

 person:       Kevin Gaines
 nic-hdl:      AYB277-IEDR
 source:       IEDR

 person:       Lets Host Domain Services
 nic-hdl:      ABG704-IEDR
 source:       IEDR
 */
public class IeParser extends AParser{
    private IeParser(){}

    private static IeParser instance = null;

    public static IeParser getInstance(){
        if(instance == null){
            instance = new IeParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*domain:\\s*[^\\n]+";
    private final String CONTACTREG = "\\s*admin\\-c:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*registration:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*renewal:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd-MMM-yyyy", Locale.ENGLISH);

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
