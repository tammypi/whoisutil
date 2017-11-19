package com.antiphishing.utils.whoisparsers;
import com.sun.org.apache.xpath.internal.operations.Or;

import java.io.Serializable;
/**
 * Created by dell on 2017/11/14.
 */
public class WhoisParserFactory implements Serializable{
    private static WhoisParserFactory whoisParserFactory = null;

    private WhoisParserFactory(){}

    public static WhoisParserFactory getInstance(){
        if(whoisParserFactory == null){
            whoisParserFactory = new WhoisParserFactory();
        }
        return whoisParserFactory;
    }

    public AParser getParser(String whoisServer){
        if(whoisServer.equals("whois.nic.it")){
            return ItParser.getInstance();
        }else if(whoisServer.equals("whois.nic.mx")){
            return MxParser.getInstance();
        }else if(whoisServer.equals("whois.neulevel.biz")){
            return BizParser.getInstance();
        }else if(whoisServer.equals("whois.ripn.net")){
            return SuParser.getInstance();
        }else if(whoisServer.equals("whois.nic.ir")){
            return IrParser.getInstance();
        }else if(whoisServer.equals("whois.nic.as")){
            return AsParser.getInstance();
        }else if(whoisServer.equals("whois.srs.net.nz")){
            return NzParser.getInstance();
        }else if(whoisServer.equals("whois.afilias.net")){
            return InfoParser.getInstance();
        }else if(whoisServer.equals("whois.nic.at")){
            return AtParser.getInstance();
        }else if(whoisServer.equals("whois.ripe.net")){
            return RipeParser.getInstance();
        }else if(whoisServer.equals("whois.norid.no")){
            return NoParser.getInstance();
        }else if(whoisServer.equals("whois.domain-registry.nl")){
            return NlParser.getInstance();
        }else if(whoisServer.equals("whois.nic.gov")){
            return GovParser.getInstance();
        }else if(whoisServer.equals("whois.nic.uk")){
            return UkParser.getInstance();
        }else if(whoisServer.equals("whois.inregistry.net")){
            return InParser.getInstance();
        }else if(whoisServer.equals("whois.jp")){
            return JpParser.getInstance();
        }else if(whoisServer.equals("whois.ja.net")){
            return JaParser.getInstance();
        }else if(whoisServer.equals("whois.nic.ac")){
            return AcParser.getInstance();
        }else if(whoisServer.equals("whois.dk-hostmaster.dk")){
            return DkParser.getInstance();
        }else if(whoisServer.equals("whois.nic.us")){
            return UsParser.getInstance();
        }else if(whoisServer.equals("whois.amnic.net")){
            return AmParser.getInstance();
        }else if(whoisServer.equals("whois.nic.nu")){
            return NuParser.getInstance();
        }else if(whoisServer.equals("whois.domainregistry.ie")){
            return IeParser.getInstance();
        }else if(whoisServer.equals("whois.nic.br")){
            return BrParser.getInstance();
        }else if(whoisServer.equals("whois.iana.org")){
            return IntParser.getInstance();
        }else if(whoisServer.equals("whois.nic.fr")){
            return FrParser.getInstance();
        }else if(whoisServer.equals("whois.nic-se.se")){
            return SeParser.getInstance();
        }else if(whoisServer.equals("whois.cnnic.net.cn")){
            return CnParser.getInstance();
        }else if(whoisServer.equals("whois.isoc.org.il")){
            return IlParser.getInstance();
        }else if(whoisServer.equals("whois.aero")){
            return AeroParser.getInstance();
        }else if(whoisServer.equals("whois.nic.name")) {
            return NameParser.getInstance();
        }else if(whoisServer.equals("whois.dns.be")){
            return BeParser.getInstance();
        }else if(whoisServer.equals("whois.denic.de")){
            return DeParser.getInstance();
        }else if(whoisServer.equals("whois.nic.museum")){
            return MuseumParser.getInstance();
        }else if(whoisServer.equals("whois.twnic.net")){
            return TwParser.getInstance();
        }else if(whoisServer.equals("whois.aunic.net")){
            return AuParser.getInstance();
        }else if(whoisServer.equals("tvwhois.verisign-grs.com")){
            return TvParser.getInstance();
        }else if(whoisServer.equals("whois.nic.sh")){
            return ShParser.getInstance();
        }else if(whoisServer.equals("whois.nic.cc")){
            return CcParser.getInstance();
        }else if(whoisServer.equals("whois.kr")){
            return KrParser.getInstance();
        }else if(whoisServer.equals("whois.website.ws")){
            return WsParser.getInstance();
        }else if(whoisServer.equals("whois.eenet.ee")){
            return EeParser.getInstance();
        }else if(whoisServer.equals("whois.dns.lu")){
            return LuParser.getInstance();
        }else if(whoisServer.equals("whois.thnic.net")){
            return ThParser.getInstance();
        }else if(whoisServer.equals("whois.hkirc.hk")){
            return HkParser.getInstance();
        }else if(whoisServer.equals("whois.eu")){
            return EuParser.getInstance();
        }else if(whoisServer.equals("whois.crsnic.net")){
            return CrParser.getInstance();
        }else if(whoisServer.equals("whois.dns.pl")){
            return PlParser.getInstance();
        }else if(whoisServer.equals("whois.educause.net")){
            return EduParser.getInstance();
        }else if(whoisServer.equals("whois.tcinet.ru")){
            return RuParser.getInstance();
        }else if(whoisServer.equals("whois.ausregistry.net.au")){
            return AusParser.getInstance();
        }else if(whoisServer.equals("whois.publicinterestregistry.net")){
            return OrgParser.getInstance();
        }else if(whoisServer.equals("whois.nic.coop")){
            return CoopParser.getInstance();
        }
        return ItParser.getInstance();
    }
}
