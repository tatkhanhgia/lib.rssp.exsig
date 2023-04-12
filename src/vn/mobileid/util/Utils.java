/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package vn.mobileid.util;

import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import vn.mobileid.keystore._LibCertStore;

public class Utils {

    private static String localPath;
    private static final HashMap<String, X509Certificate> certMap = new HashMap<>();

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
            createTempFolder(System.getProperty("java.io.tmpdir"));
        } catch (Exception ex) {
            try {
                ex.printStackTrace();
                createTempFolder(Utils.class.getProtectionDomain().getCodeSource().getLocation().getPath());
            } catch (Exception ex1) {
                ex.printStackTrace();
            }
        }
    }

    public static byte[] loadFile(String path) throws IOException {
        return Files.readAllBytes(new File(path).toPath());
    }

    static void createTempFolder(String path) throws Exception {
        File filePath = new File(path);
        path = filePath + "/";
        File tempPath = new File(path + "RemoteSigning/");
        if (!Files.exists(tempPath.toPath())) {
            if (!new File(tempPath.getPath()).mkdir()) {
                throw new Exception("Can't create RemoteSigning folder");
            }
        }

        localPath = tempPath.toString();

        File crlPath = new File(tempPath.getPath() + "/crl/");
        if (!Files.exists(crlPath.toPath())) {
            if (!new File(crlPath.getPath()).mkdir()) {
                throw new Exception("Can't create RemoteSigning/crl folder");
            }
        }

        File certPath = new File(tempPath.getPath() + "/cert/");
        if (!Files.exists(certPath.toPath())) {
            if (!new File(certPath.getPath()).mkdir()) {
                throw new Exception("Can't create temp/cert folder");
            }
            KeyStore certStore = new _LibCertStore().getKeyStoreJKS("certStore.jks", "hoann01120506");
            Enumeration aliases = certStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                X509Certificate cert = (X509Certificate) certStore.getCertificate(alias);
                byte[] certBytes = cert.getEncoded();
                try ( FileOutputStream fos = new FileOutputStream(certPath.getPath() + "/" + cert.getSerialNumber() + ".cer")) {
                    fos.write(certBytes);
                }
            }
        }
    }

    public static List<X509CRL> getCrlFormCerts(List<X509Certificate> certs) throws Exception {

        List<X509CRL> crls = new ArrayList<>();
        for (X509Certificate cert : certs) {
            List<String> urls = getCrlUrl(cert);
            if (urls != null) {
                File tempPath = new File(localPath + "/crl/");
                if (!Files.exists(tempPath.toPath())) {
                    for (String url : urls) {
                        String crlFile = new String(Base64.getEncoder().encode(url.getBytes()));
                        crls.addAll(GetCrlFormUrl(crlFile, url));
                    }
                } else {
                    for (String url : urls) {
                        String crlFile = new String(Base64.getEncoder().encode(url.getBytes()));
                        byte[] data;
                        try {
                            File file = new File(localPath + "/crl/" + crlFile + ".crl");
                            data = Files.readAllBytes(file.toPath());
                        } catch (IOException ex) {
                            data = null;
                        }
                        if (data != null) {
                            InputStream inputStream = new ByteArrayInputStream(data);
                            CertificateFactory cf = new CertificateFactory();
                            Collection<X509CRL> crl = cf.engineGenerateCRLs(inputStream);
                            if (crl == null) {
                                inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(data));
                                crl = cf.engineGenerateCRLs(inputStream);
                            }
                            for (X509CRL x509crl : crl) {
                                if (x509crl.getNextUpdate().getTime() < Calendar.getInstance().getTimeInMillis()) {
                                    data = null;
                                    break;
                                }
                            }
                            if (data != null) {
                                crls.addAll(crl);
                            }
                        }
                        if (data == null) {
                            crls.addAll(GetCrlFormUrl(crlFile, url));
                        }
                    }
                }
            }
        }
        if (!crls.isEmpty()) {
            return crls;
        } else {
            return null;
        }
    }

    static Collection<X509CRL> GetCrlFormUrl(String crlFile, String url) throws Exception {

//        if(url.equals("http://public.rootca.gov.vn/crl/micnrca.crl")){
//            url = "https://rootca.gov.vn/crl/micnrca.crl";
//        }
        HttpURLConnection con = (HttpURLConnection) getFinalURL(new URL(url)).openConnection();
        ByteArrayOutputStream bout;

        try ( BufferedInputStream inp = new BufferedInputStream(con.getInputStream())) {
            byte[] buf = new byte[1024];
            bout = new ByteArrayOutputStream();
            while (true) {
                int n = inp.read(buf, 0, buf.length);
                if (n <= 0) {
                    break;
                }
                bout.write(buf, 0, n);
            }
        }
        try ( FileOutputStream fos = new FileOutputStream(localPath + "/crl/" + crlFile + ".crl")) {
            fos.write(bout.toByteArray());
        } catch (Exception ex) {
            throw new Exception("Can't save crls : " + ex.getMessage());
        }
        InputStream inputStream = new ByteArrayInputStream(bout.toByteArray());
        CertificateFactory cf = new CertificateFactory();
        Collection<X509CRL> crl = cf.engineGenerateCRLs(inputStream);
        if (crl == null) {
            inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(bout.toByteArray()));
            crl = cf.engineGenerateCRLs(inputStream);
        }
        return crl;
    }

    private static List<String> getCrlUrl(X509Certificate certificate) {
        List<String> crlUrls = new ArrayList<>();
        try {
            byte[] crlDistributionPointDerEncodedArray = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
            if (crlDistributionPointDerEncodedArray != null) {

                DEROctetString dosCrlDP;
                try ( ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crlDistributionPointDerEncodedArray))) {
                    ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
                    dosCrlDP = (DEROctetString) derObjCrlDP;
                }
                byte[] crldpExtOctets = dosCrlDP.getOctets();
                CRLDistPoint distPoint;
                try ( ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets))) {
                    ASN1Primitive derObj2 = oAsnInStream2.readObject();
                    distPoint = CRLDistPoint.getInstance(derObj2);
                }

                for (DistributionPoint dp : distPoint.getDistributionPoints()) {
                    DistributionPointName dpn = dp.getDistributionPoint();
                    // Look for URIs in fullName
                    if (dpn != null) {
                        if (dpn.getType() == DistributionPointName.FULL_NAME) {
                            GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                            // Look for an URI
                            for (GeneralName genName : genNames) {
                                if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                    String url = DERIA5String.getInstance(genName.getName()).getString();
                                    crlUrls.add(url);
                                }
                            }
                        }
                    }
                }
            }
            if (!crlUrls.isEmpty()) {
                return crlUrls;
            } else {
                return null;
            }
        } catch (IOException e) {
            System.err.println("Can't load certificate : " + e.getMessage());
            return null;
        }
    }

    static URL getFinalURL(URL url) {
        try {
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setInstanceFollowRedirects(false);
            con.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36");
            con.addRequestProperty("Accept-Language", "en-US,en;q=0.8");
            con.addRequestProperty("Referer", "https://www.google.com/");
            con.connect();
            int resCode = con.getResponseCode();
            if (resCode == HttpURLConnection.HTTP_SEE_OTHER
                    || resCode == HttpURLConnection.HTTP_MOVED_PERM
                    || resCode == HttpURLConnection.HTTP_MOVED_TEMP) {
                String Location = con.getHeaderField("Location");
                if (Location.startsWith("/")) {
                    Location = url.getProtocol() + "://" + url.getHost() + Location;
                }
                return getFinalURL(new URL(Location));
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
        return url;
    }

    public static List<X509Certificate> getCertPath(
            X509Certificate certificate,
            boolean revocationEnabled,
            Date date,
            List<X509Certificate> x509Certs,
            List<X509CRL> x509Crls) throws Exception {

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(certificate);
        return validate(selector, date, revocationEnabled, 4, x509Certs, x509Crls);
    }

    static List<X509Certificate> getCertPath(
            X509Certificate certificate,
            boolean revocationEnabled,
            Date date,
            List<X509Certificate> x509Certs) throws Exception {
        return getCertPath(certificate, revocationEnabled, date, x509Certs, null);
    }

    public static ArrayList<X509Certificate> getCertPath(
            X509Certificate certificate) throws Exception {
        File tempPath = new File(localPath + "/cert");
        FileSystemDirectoryCertStore store = new FileSystemDirectoryCertStore(tempPath.getPath());
        Collection<X509Certificate> c = (Collection<X509Certificate>) store.getStore().getCertificates(new CertSelector() {
            @Override
            public boolean match(Certificate crtfct) {
                return true;
            }

            @Override
            public Object clone() {
                return this;
            }
        });
        List<X509Certificate> certFormTempFolder = new ArrayList<>();
        certFormTempFolder.add(certificate);
        certFormTempFolder.addAll(c);

        Date date = Calendar.getInstance().getTime();
        return new ArrayList<>(getCertPath(certificate, false, date, certFormTempFolder));
    }

    public static boolean checkCertificateRevocation2(X509Certificate certificate) {
        try {

            List<X509Certificate> certList = Utils.getCertPath(certificate);
            List<X509CRL> crlList = getCrlFormCerts(Utils.getCertPath(certificate));
            Utils.getCertPath(certificate, true, Calendar.getInstance().getTime(), certList, crlList);
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }

    public static List<X509Certificate> checkCertificateRevocation(X509Certificate certificate) {
        try {

            List<X509Certificate> certList = Utils.getCertPath(certificate);
            List<X509CRL> crlList = getCrlFormCerts(Utils.getCertPath(certificate));
            return Utils.getCertPath(certificate, true, Calendar.getInstance().getTime(), certList, crlList);

        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    public static String timeMilsToString(long timeMils) {
        Date date = new Date(timeMils);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        return sdf.format(date);
    }

    public static List<X509Certificate> getCertificatePath(X509Certificate certificate) throws Exception {
        List<X509Certificate> certs = Utils.getCertPath(certificate);
        List<X509CRL> crlList = getCrlFormCerts(Utils.getCertPath(certificate));
        return Utils.getCertPath(certificate, true, Calendar.getInstance().getTime(), certs, crlList);
    }

    public static byte[] hashData(byte[] data, String hashAlgorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
            return md.digest(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void printXmlDocument(Document xmlDocument) throws TransformerConfigurationException, TransformerException {
        TransformerFactory tf = javax.xml.transform.TransformerFactory.newInstance();
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer transformer;
        transformer = tf.newTransformer();
        StringWriter writer = new StringWriter();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        System.out.println(3);
        transformer.transform(new DOMSource(xmlDocument), new StreamResult(writer));
        String xmlString = writer.getBuffer().toString();
        System.out.println(xmlString);                      //Print to console or logs
    }

    public static void writeXmlDocument(Document xmlDocument, String fileName) throws Exception {
        TransformerFactory tFactory = javax.xml.transform.TransformerFactory.newInstance();
        tFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        tFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer transformer = tFactory.newTransformer();
        DOMSource source = new DOMSource(xmlDocument);
        try ( FileOutputStream fos = new FileOutputStream(fileName)) {
            StreamResult result = new StreamResult(fos);
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            System.out.println(2);
            transformer.transform(source, result);
        }
    }

    public static byte[] writeXmlDocument(Document xmlDocument) throws Exception {
        TransformerFactory tFactory = javax.xml.transform.TransformerFactory.newInstance();
        tFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        tFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer transformer = tFactory.newTransformer();
        DOMSource source = new DOMSource(xmlDocument);
        byte[] data;
        try ( ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            StreamResult result = new StreamResult(baos);
            transformer.setOutputProperty(OutputKeys.STANDALONE, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.transform(source, result);
            data = baos.toByteArray();
        }
        return data;
    }

    public static Document getXmlDocument(byte[] data) throws SAXException, ParserConfigurationException, IOException {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        docBuilderFactory.setNamespaceAware(true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        return docBuilder.parse(bais);
    }

    public static Document getNewXmlDocument() throws SAXException, ParserConfigurationException, IOException {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        docBuilderFactory.setNamespaceAware(true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        return docBuilder.newDocument();
    }

    static byte[] inputStreamToByteArray(InputStream inputStream) {
        ByteArrayOutputStream bout;
        try ( BufferedInputStream inp = new BufferedInputStream(inputStream)) {
            byte[] buf = new byte[1024];
            bout = new ByteArrayOutputStream();
            while (true) {
                int n = inp.read(buf, 0, buf.length);
                if (n <= 0) {
                    break;
                }
                bout.write(buf, 0, n);
            }
            return bout.toByteArray();
        } catch (IOException ex) {
            //Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static Document loadXmlDocument(byte[] src) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        docBuilderFactory.setNamespaceAware(true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        return docBuilder.parse(new ByteArrayInputStream(src));
    }

    //Update 4/7/2022
    public static List<X509Certificate> validate(
            X509CertSelector certSelector,
            Date validationDate,
            boolean revocationEnabled,
            int maxLenght,
            List<X509Certificate> certList,
            List<X509CRL> crlList) throws Exception {

        CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
        HashSet rootCerts = new HashSet();
        List<X509Certificate> newCertList = new ArrayList<>();
        for (X509Certificate x509Cert : certList) {
            //@Deprecated => Using another method
            if (x509Cert.getIssuerDN().equals(x509Cert.getSubjectDN())) {
                rootCerts.add(new TrustAnchor(x509Cert, null));
            } //            if (x509Cert.getIssuerX500Principal().equals(x509Cert.getSubjectX500Principal())) {
            //                rootCerts.add(new TrustAnchor(x509Cert, null));
            //            } 
            else {
                newCertList.add(x509Cert);
            }
        }
        if (rootCerts.isEmpty()) {
            for (String key : certMap.keySet()) {
                X509Certificate c = certMap.get(key);
                if (c.getIssuerDN().equals(c.getSubjectDN())) {
                    rootCerts.add(new TrustAnchor(c, null));
                } else {
                    newCertList.add(c);
                }
            }
        }

        PKIXBuilderParameters params;
        try {
            params = new PKIXBuilderParameters(rootCerts, certSelector);
            params.setDate(validationDate);
            params.setRevocationEnabled(revocationEnabled);
            params.setMaxPathLength(4);
            params.setSigProvider("BC");
            if (!newCertList.isEmpty()) {
                CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(newCertList);
                CertStore othersCertStore = CertStore.getInstance("Collection", ccsp);
                params.addCertStore(othersCertStore);
            }
            if (revocationEnabled) {
                if (!crlList.isEmpty()) {
                    CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(crlList);
                    CertStore othersCertStore = CertStore.getInstance("Collection", ccsp);
                    params.addCertStore(othersCertStore);
                } else {
                    throw new Exception("Crl list can't be null");
                }
            }

        } catch (InvalidAlgorithmParameterException ex) {
            throw new Exception("Trust anchors KeyStore has no trusted certificate entries", ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new Exception("Can't create Certstore", ex);
        }

        try {
            CertPathBuilderResult certPathBuilderResult = certPathBuilder.build(params);
            PKIXCertPathBuilderResult builderRes = (PKIXCertPathBuilderResult) certPathBuilderResult;
            List<X509Certificate> certPath = (List<X509Certificate>) builderRes.getCertPath().getCertificates();
            certPath = new ArrayList<X509Certificate>(certPath);
            X509Certificate root = builderRes.getTrustAnchor().getTrustedCert();
            certPath.add(root);
            if (revocationEnabled) {
                CertPath cp = certPathBuilderResult.getCertPath();
                CertPathValidator pathValidator = CertPathValidator.getInstance(CertPathBuilder.getDefaultType());
                CertPathValidatorResult result = pathValidator.validate(cp, params);
                if (result == null) {
                    throw new Exception("Invalid revocation data");
                }
            }
            return certPath;
        } catch (InvalidAlgorithmParameterException ex) {
            String q = ex.getMessage();
            throw new Exception(ex.getMessage(), ex);
        } catch (CertPathBuilderException ex) {
            String q = ex.getMessage();
            throw new Exception(ex.getMessage(), ex);
        }
    }

    public static void addTrustStore(X509Certificate cert) throws Exception {
        String key = hashSha256(cert.getEncoded());
        certMap.put(key, cert);
    }

    public static void addTrustStore(String base64) throws Exception {
        InputStream inputStream = new ByteArrayInputStream(org.bouncycastle.util.encoders.Base64.decode(base64));
        CertificateFactory cf = new CertificateFactory();
        Collection<X509Certificate> certs = cf.engineGenerateCertificates(inputStream);
        for (X509Certificate cert : certs) {
            String key = hashSha256(cert.getEncoded());
            certMap.put(key, cert);
        }
    }

    public static String hashSha256(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] hashedString = messageDigest.digest(data);
        return org.bouncycastle.util.encoders.Base64.toBase64String(hashedString);
    }

}
