package com.antiphishing.utils.whoisparsers;

import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;

/**
 * Created by dell on 2017/11/17.
 */

/**
 * # KOREAN(UTF8)

 도메인이름                  : test.kr
 등록인                      : 한국인터넷진흥원
 등록인 주소                 : 서울시 송파구 중대로 135 IT벤처타워
 등록인 우편번호             : 05717
 책임자                      : 도메인관리자
 책임자 전자우편             : domain-manager@nic.or.kr
 책임자 전화번호             : 02-405-5118
 등록일                      : 2007. 08. 21.
 최근 정보 변경일            : 2009. 12. 15.
 사용 종료일                 : 9999. 12. 31.
 정보공개여부                : Y
 등록대행자                  : 한국인터넷진흥원(http://www.kisa.or.kr)
 DNSSEC                      : 미서명
 등록정보 보호               : serverDeleteProhibited
 등록정보 보호               : serverTransferProhibited
 등록정보 보호               : serverUpdateProhibited

 1차 네임서버 정보
 호스트이름               : ns1.test.kr
 IP 주소                  : 202.31.188.2

 2차 네임서버 정보
 호스트이름               : ns2.test.kr
 IP 주소                  : 202.31.188.3
 호스트이름               : ns1.test.kr
 IP 주소                  : 2001:2b8:a1:1::2
 호스트이름               : ns2.test.kr
 IP 주소                  : 2001:2b8:a1:1::3

 네임서버 이름이 .kr이 아닌 경우는 IP주소가 보이지 않습니다.


 # ENGLISH

 Domain Name                 : test.kr
 Registrant                  : Korea Internet & Security Agency
 Registrant Address          : KISA, IT Venture Tower, Jungdaero 135, Songpa-gu, Seoul, Korea
 Registrant Zip Code         : 05717
 Administrative Contact(AC)  : Domain Manager
 AC E-Mail                   : domain-manager@nic.or.kr
 AC Phone Number             : 02-405-5118
 Registered Date             : 2007. 08. 21.
 Last Updated Date           : 2009. 12. 15.
 Expiration Date             : 9999. 12. 31.
 Publishes                   : Y
 Authorized Agency           : KISA(http://www.kisa.or.kr)
 DNSSEC                      : unsigned
 Domain Status               : serverDeleteProhibited
 Domain Status               : serverTransferProhibited
 Domain Status               : serverUpdateProhibited

 Primary Name Server
 Host Name                : ns1.test.kr
 IP Address               : 202.31.188.2

 Secondary Name Server
 Host Name                : ns2.test.kr
 IP Address               : 202.31.188.3
 Host Name                : ns1.test.kr
 IP Address               : 2001:2b8:a1:1::2
 Host Name                : ns2.test.kr
 IP Address               : 2001:2b8:a1:1::3



 - KISA/KRNIC WHOIS Service -
 */
public class KrParser extends AParser{
    private KrParser(){}

    private static KrParser instance = null;

    public static KrParser getInstance(){
        if(instance == null){
            instance = new KrParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name\\s*:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*Registrant\\s*:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Registered Date\\s*:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Last Updated Date\\s*:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactsPattern = Pattern.compile(CONTACTSREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy'.' MM'.' dd'.'");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
            String contacts = getFieldValue(getMatchField(contactsPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
