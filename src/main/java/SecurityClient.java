import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.om.impl.llom.util.AXIOMUtil;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.rampart.RampartMessageData;
import org.apache.rampart.policy.model.CryptoConfig;
import org.apache.rampart.policy.model.RampartConfig;
import org.apache.ws.security.WSPasswordCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.Properties;

public class SecurityClient implements CallbackHandler {

    public static void main(String srgs[]) {

        SecurityClient securityCl = new SecurityClient();
        OMElement result = null;
        try {
            result = securityCl.runSecurityClient();
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println(result.toString());

    }

    public OMElement runSecurityClient() throws Exception {

        Properties properties = new Properties();
        FileInputStream fileInputStream = new FileInputStream("/home/firzhan/wso2/JIRA/public/POX-Handler/qos/security-client/src/main/resources/client.properties");
        properties.load(fileInputStream);

        String clientRepo = properties.getProperty("clientRepo");
        String endpointHttpS = properties.getProperty("endpointHttpS");
        String serviceName = properties.getProperty("serviceName");
        String endpointHttp = properties.getProperty("endpointHttp");

     /*   endpointHttpS =
                endpointHttpS.endsWith("/") ? endpointHttpS + serviceName : endpointHttpS +"/" + serviceName;

        endpointHttp =
                endpointHttp.endsWith("/") ? endpointHttp + serviceName : endpointHttp +"/" + serviceName;
*/
        int securityScenario = Integer.parseInt(properties.getProperty("securityScenarioNo"));
        String clientKey = properties.getProperty("clientKey");
        String SoapAction = properties.getProperty("SoapAction");
        String body = properties.getProperty("body");
        String userName = properties.getProperty("userName");
        String trustStore = properties.getProperty("trustStore");
        String securityPolicy = properties.getProperty("securityPolicyLocation");

        OMElement result = null;


        System.setProperty("javax.net.ssl.trustStore", trustStore);
        System.setProperty("javax.net.ssl.trustStorePassword", "wso2carbon");

        //System.setProperty("javax.net.ssl.keyStore", keyStore + File.separator +  "wso2carbon.jks");
        //System.setProperty("javax.net.ssl.keyStorePassword", "wso2carbon");

        ConfigurationContext ctx = ConfigurationContextFactory.createConfigurationContextFromFileSystem(clientRepo, null);
        ServiceClient sc = new ServiceClient(ctx, null);
        sc.engageModule("rampart");
        sc.engageModule("addressing");

        Options opts = new Options();

        if (securityScenario == 1) {
            opts.setTo(new EndpointReference(endpointHttpS));
        } else {
            opts.setTo(new EndpointReference(endpointHttp));
        }

        opts.setAction(SoapAction);

       /* QName securityHeader = new QName("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                "Security");
        HashSet<QName> headers = new HashSet<QName>();
        headers.add(securityHeader);*/

        //opts.setProperty(org.apache.axis2.transport.http.HTTPConstants.HTTP_HEADERS, headers);

       /* InflowConfigurataion ifc = new InflowConfiguration();
        ifc.setActionItems("Timestamp");

        Parameter parm = ifc.getProperty();
        opts.setProperty(WSSHandlerConstants.INFLOW_SECURITY, parm);*/


        if (securityScenario != 0) {
            try {
                String securityPolicyPath = securityPolicy + File.separator + "scenario" + securityScenario + "-policy.xml";
                opts.setProperty(RampartMessageData.KEY_RAMPART_POLICY, loadPolicy(securityScenario, securityPolicyPath, clientKey, userName));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        sc.setOptions(opts);
        result = sc.sendReceive(AXIOMUtil.stringToOM(body));
        System.out.println(result.getFirstElement().getText());
        return result;
    }

    public Policy loadPolicy(int securityScenario, String xmlPath, String clientKey, String userName) throws Exception {

        StAXOMBuilder builder = new StAXOMBuilder(xmlPath);
        Policy policy = PolicyEngine.getPolicy(builder.getDocumentElement());

        if (securityScenario != 16) {   // Skip for Kerberos scenario
            RampartConfig rc = new RampartConfig();


            rc.setUser(userName);
            rc.setUserCertAlias("wso2carbon");
            rc.setEncryptionUser("wso2carbon");
            rc.setPwCbClass(SecurityClient.class.getName());

            CryptoConfig sigCryptoConfig = new CryptoConfig();
            sigCryptoConfig.setProvider("org.apache.ws.security.components.crypto.Merlin");

            Properties prop1 = new Properties();
            prop1.put("org.apache.ws.security.crypto.merlin.keystore.type", "JKS");
            prop1.put("org.apache.ws.security.crypto.merlin.file", clientKey);
            prop1.put("org.apache.ws.security.crypto.merlin.keystore.password", "wso2carbon");
            sigCryptoConfig.setProp(prop1);

            CryptoConfig encrCryptoConfig = new CryptoConfig();
            encrCryptoConfig.setProvider("org.apache.ws.security.components.crypto.Merlin");

            Properties prop2 = new Properties();
            prop2.put("org.apache.ws.security.crypto.merlin.keystore.type", "JKS");
            prop2.put("org.apache.ws.security.crypto.merlin.file", clientKey);
            prop2.put("org.apache.ws.security.crypto.merlin.keystore.password", "wso2carbon");
            encrCryptoConfig.setProp(prop2);

            rc.setSigCryptoConfig(sigCryptoConfig);
            rc.setEncrCryptoConfig(encrCryptoConfig);

            policy.addAssertion(rc);
        }
        return policy;
    }


    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        WSPasswordCallback pwcb = (WSPasswordCallback) callbacks[0];
        String id = pwcb.getIdentifer();
        int usage = pwcb.getUsage();

        if (usage == WSPasswordCallback.USERNAME_TOKEN) {

            if ("admin".equals(id)) {
                pwcb.setPassword("admin");
            } else if ("admin@wso2.com".equals(id)) {
                pwcb.setPassword("admin123");
            }else if ("alice".equals(id)) {
                pwcb.setPassword("bobPW");
            }else if ("alice@carbon.super".equals(id)) {
                pwcb.setPassword("bobPW");
            }

        } else if (usage == WSPasswordCallback.SIGNATURE || usage == WSPasswordCallback.DECRYPT) {

            if ("wso2carbon".equals(id)) {
                pwcb.setPassword("wso2carbon");
            }else if ("alice".equals(id)) {
                pwcb.setPassword("bobPW");
            }else if ("alice@carbon.super".equals(id)) {
                pwcb.setPassword("bobPW");
            }
        }
    }
}