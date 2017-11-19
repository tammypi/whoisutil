package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/14.
 */

/**
 * Domain Name:       aaa.mx

 Created On:        2009-05-31
 Expiration Date:   2018-05-30
 Last Updated On:   2017-07-16
 Registrar:         Wingu Networks S.A de C.V.
 URL:               http://www.suempresa.com

 Registrant:
 Name:           HMC
 City:           San Ysidro
 State:          California
 Country:        United States

 Administrative Contact:
 Name:           Hae Mi Choi Lee
 City:           San Ysidro
 State:          California
 Country:        United States

 Technical Contact:
 Name:           Hae Mi Choi Lee
 City:           San Ysidro
 State:          California
 Country:        United States

 Billing Contact:
 Name:           Hae Mi Choi Lee
 City:           San Ysidro
 State:          California
 Country:        United States

 Name Servers:
 DNS:            ns1.sedoparking.com
 DNS:            ns2.sedoparking.com

 DNSSEC DS Records:


 % NOTICE: The expiration date displayed in this record is the date the
 % registrar's sponsorship of the domain name registration in the registry is
 % currently set to expire. This date does not necessarily reflect the
 % expiration date of the domain name registrant's agreement with the sponsoring
 % registrar. Users may consult the sponsoring registrar's Whois database to
 % view the registrar's reported date of expiration for this registration.

 % The requested information ("Information") is provided only for the delegation
 % of domain names and the operation of the DNS administered by NIC Mexico.

 % It is absolutely prohibited to use the Information for other purposes,
 % including sending not requested emails for advertising or promoting products
 % and services purposes (SPAM) without the authorization of the owners of the
 % Information and NIC Mexico.

 % The database generated from the delegation system is protected by the
 % intellectual property laws and all international treaties on the matter.

 % If you need more information on the records displayed here, please contact us
 % by email at ayuda@nic.mx .

 % If you want notify the receipt of SPAM or unauthorized access, please send a
 % email to abuse@nic.mx .

 % NOTA: La fecha de expiracion mostrada en esta consulta es la fecha que el
 % registrar tiene contratada para el nombre de dominio en el registry. Esta
 % fecha no necesariamente refleja la fecha de expiracion del nombre de dominio
 % que el registrante tiene contratada con el registrar. Puede consultar la base
 % de datos de Whois del registrar para ver la fecha de expiracion reportada por
 % el registrar para este nombre de dominio.

 % La informacion que ha solicitado se provee exclusivamente para fines
 % relacionados con la delegacion de nombres de dominio y la operacion del DNS
 % administrado por NIC Mexico.

 % Queda absolutamente prohibido su uso para otros propositos, incluyendo el
 % envio de Correos Electronicos no solicitados con fines publicitarios o de
 % promocion de productos y servicios (SPAM) sin mediar la autorizacion de los
 % afectados y de NIC Mexico.

 % La base de datos generada a partir del sistema de delegacion, esta protegida
 % por las leyes de Propiedad Intelectual y todos los tratados internacionales
 % sobre la materia.

 % Si necesita mayor informacion sobre los registros aqui mostrados, favor de
 % comunicarse a ayuda@nic.mx.

 % Si desea notificar sobre correo no solicitado o accesos no autorizados, favor
 % de enviar su mensaje a abuse@nic.mx.
 */
public class MxParser extends AParser{
    private MxParser(){}
    private static MxParser instance = null;

    public static MxParser getInstance(){
        if(instance == null){
            instance = new MxParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain\\sName:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\sAdministrative Contact:\\r\\n\\s*Name:\\s*[^\\n]+";
    private final String ORGNIZATIONREG = "\\s*Registrar:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Created On:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Last Updated On:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);
    private Pattern orgnizationPattern = Pattern.compile(ORGNIZATIONREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), "Name:");
            whoisModel.setContacts(contacts);
            String orgnization = getFieldValue(getMatchField(orgnizationPattern, whoisResponse), ":");
            whoisModel.setOrgnization(orgnization);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime.trim()).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime.trim()).getTime());
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
