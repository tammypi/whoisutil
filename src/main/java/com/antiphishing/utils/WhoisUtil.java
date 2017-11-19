package com.antiphishing.utils;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.whoisparsers.WhoisParserFactory;
import org.apache.commons.net.whois.WhoisClient;
import org.parboiled.common.Tuple2;

import java.io.IOException;
import java.io.Serializable;
import java.net.URL;
import java.util.*;

/**
 * Created by dell on 2017/11/14.
 */
public class WhoisUtil implements Serializable{
    private static String ipMapStr = ".br.com       whois.centralnic.com\n" +
            ".cn.com       whois.centralnic.com\n" +
            ".de.com       whois.centralnic.com\n" +
            ".eu.com       whois.centralnic.com\n" +
            ".gb.com       whois.centralnic.com\n" +
            ".gb.net       whois.centralnic.com\n" +
            ".hu.com       whois.centralnic.com\n" +
            ".no.com       whois.centralnic.com\n" +
            ".qc.com       whois.centralnic.com\n" +
            ".ru.com       whois.centralnic.com\n" +
            ".sa.com       whois.centralnic.com\n" +
            ".se.com       whois.centralnic.com\n" +
            ".se.net       whois.centralnic.com\n" +
            ".uk.com       whois.centralnic.com\n" +
            ".uk.net       whois.centralnic.com\n" +
            ".us.com       whois.centralnic.com\n" +
            ".uy.com       whois.centralnic.com\n" +
            ".za.com       whois.centralnic.com\n" +
            ".com.au       whois.ausregistry.net.au\n" +
            ".net.au       whois.ausregistry.net.au\n" +
            ".org.au       whois.ausregistry.net.au\n" +
            ".asn.au       whois.ausregistry.net.au\n" +
            ".id.au        whois.ausregistry.net.au\n" +
            ".ac.uk        whois.ja.net\n" +
            ".gov.uk       whois.ja.net\n" +
            ".museum       whois.nic.museum\n" +
            ".asia         whois.crsnic.net\n" +
            ".info         whois.afilias.net\n" +
            ".name         whois.nic.name\n" +
            ".aero         whois.aero\n" +
            ".coop         whois.nic.coop\n" +
            ".com          whois.crsnic.net\n" +
            ".net          whois.crsnic.net\n" +
            ".org          whois.publicinterestregistry.net\n" +
            ".edu          whois.educause.net\n" +
            ".gov          whois.nic.gov\n" +
            ".int          whois.iana.org\n" +
            ".mil          whois.nic.mil\n" +
            ".biz          whois.neulevel.biz\n" +
            ".as           whois.nic.as\n" +
            ".ac           whois.nic.ac\n" +
            ".al           whois.ripe.net\n" +
            ".am           whois.amnic.net\n" +
            ".at           whois.nic.at\n" +
            ".au           whois.aunic.net\n" +
            ".az           whois.ripe.net\n" +
            ".ba           whois.ripe.net\n" +
            ".be           whois.dns.be\n" +
            ".bg           whois.ripe.net\n" +
            ".br           whois.nic.br\n" +
            ".by           whois.ripe.net\n" +
            ".ca           whois.cira.ca\n" +
            ".cc           whois.nic.cc\n" +
            ".cd           whois.nic.cd\n" +
            ".ch           whois.nic.ch\n" +
            ".cl           whois.nic.cl\n" +
            ".cn           whois.cnnic.net.cn\n" +
            ".cx           whois.nic.cx\n" +
            ".cy           whois.ripe.net\n" +
            ".cz           whois.ripe.net\n" +
            ".de           whois.denic.de\n" +
            ".dk           whois.dk-hostmaster.dk\n" +
            ".dz           whois.ripe.net\n" +
            ".ee           whois.eenet.ee\n" +
            ".eg           whois.ripe.net\n" +
            ".es           whois.ripe.net\n" +
            ".eu           whois.eu\n" +
            ".fi           whois.ripe.net\n" +
            ".fo           whois.ripe.net\n" +
            ".fr           whois.nic.fr\n" +
            ".gb           whois.ripe.net\n" +
            ".ge           whois.ripe.net\n" +
            ".gr           whois.ripe.net\n" +
            ".gs           whois.nic.gs\n" +
            ".hk           whois.hkirc.hk\n" +
            ".hr           whois.ripe.net\n" +
            ".hu           whois.ripe.net\n" +
            ".ie           whois.domainregistry.ie\n" +
            ".il           whois.isoc.org.il\n" +
            ".in           whois.inregistry.net\n" +
            ".ir           whois.nic.ir\n" +
            ".is           whois.ripe.net\n" +
            ".it           whois.nic.it\n" +
            ".jp           whois.jp\n" +
            ".kh           whois.nic.net.kh\n" +
            ".kr           whois.kr\n" +
            ".li           whois.nic.ch\n" +
            ".lt           whois.ripe.net\n" +
            ".lu           whois.dns.lu\n" +
            ".lv           whois.ripe.net\n" +
            ".ma           whois.ripe.net\n" +
            ".md           whois.ripe.net\n" +
            ".mk           whois.ripe.net\n" +
            ".ms           whois.nic.ms\n" +
            ".mt           whois.ripe.net\n" +
            ".mx           whois.nic.mx\n" +
            ".nl           whois.domain-registry.nl\n" +
            ".no           whois.norid.no\n" +
            ".nu           whois.nic.nu\n" +
            ".nz           whois.srs.net.nz\n" +
            ".pl           whois.dns.pl\n" +
            ".pt           whois.ripe.net\n" +
            ".ro           whois.ripe.net\n" +
            ".ru           whois.tcinet.ru\n" +
            ".se           whois.nic-se.se\n" +
            ".sg           whois.nic.net.sg\n" +
            ".si           whois.ripe.net\n" +
            ".sh           whois.nic.sh\n" +
            ".sk           whois.ripe.net\n" +
            ".sm           whois.ripe.net\n" +
            ".su           whois.ripn.net\n" +
            ".tc           whois.nic.tc\n" +
            ".tf           whois.nic.tf\n" +
            ".th           whois.thnic.net\n" +
            ".tj           whois.nic.tj\n" +
            ".tn           whois.ripe.net\n" +
            ".to           whois.tonic.to\n" +
            ".tr           whois.ripe.net\n" +
            ".tv           tvwhois.verisign-grs.com\n" +
            ".tw           whois.twnic.net\n" +
            ".ua           whois.ripe.net\n" +
            ".uk           whois.nic.uk\n" +
            ".us           whois.nic.us\n" +
            ".va           whois.ripe.net\n" +
            ".vg           whois.nic.vg\n" +
            ".ws           whois.website.ws";
    private static List<Tuple2<String,String>> domainServerList = new ArrayList<Tuple2<String,String>>();

    static{
        String[] lines = ipMapStr.split("\n");
        for(String line:lines){
            line = line.replaceAll("[\\s]+"," ");
            String[] items = line.split(" ");
            domainServerList.add(new Tuple2<String, String>(items[0], items[1]));
        }
    }

    public static WhoisModel queryWhois(String url){
        WhoisModel whoisModel = null;
        WhoisClient whoisClient = null;

        try{
            whoisClient = new WhoisClient();
            String host = new URL(url).getHost();
            if(host.startsWith("www.")){
                host = host.substring(4);
            }
            String curDoaminServer = WhoisClient.DEFAULT_HOST;
            for(Tuple2<String,String> tuple2:domainServerList){
                if(host.endsWith(tuple2.a)){
                    curDoaminServer = tuple2.b;
                    break;
                }
            }
            whoisClient.connect(curDoaminServer);
            String result = whoisClient.query(host);
            whoisModel = WhoisParserFactory.getInstance().getParser(curDoaminServer).parseWhois(result);
        }catch(Exception ex){
            ex.printStackTrace();
        }finally{
            if(whoisClient != null){
                try {
                    whoisClient.disconnect();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return whoisModel;
    }
}
