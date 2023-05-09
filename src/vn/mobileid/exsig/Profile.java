/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package vn.mobileid.exsig;

import vn.mobileid.util.Utils;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author USER
 */
 public abstract class Profile implements Serializable {

    protected transient int ltvSize = 0;
    protected transient int tsaSize = 0;
    protected Form form;

    protected String signatureId;
    protected Algorithm algorithm;
    protected List<X509Certificate> certificates;
    protected List<String> passwordList;
    protected String[] tsaData;
    protected String bearer;
    protected String version;

    protected long timeMillis = Calendar.getInstance().getTimeInMillis();

    public  List<byte[]> tempDataList = new ArrayList<>();
    public  List<String> hashList = new ArrayList<>();
    public  List<byte[]> crls;
    public  List<byte[]> otherList = new ArrayList<>();

    protected byte[] ocsp;
    protected String timeFormat = "yyyy-MM-dd'T'HH:mm:ss";

    protected transient boolean rootCertificate = false;

    public Profile() {
    }

    protected Profile(final Form form, final Algorithm algorithm) throws NullPointerException {
        if (form == null) {
            throw new NullPointerException("Form is null");
        }
        if (algorithm == null) {
            throw new NullPointerException("Algorithm is null");
        }
        this.form = form;
        this.algorithm = algorithm;
    }

    public void setTsaHttpData(String tsaURL) throws Exception {
        this.tsaData = new String[]{tsaURL, null, null};
    }

    public void setTsaHttpData(String tsaURL, String tsaUsername, String tsaPassword) throws Exception {
        this.tsaData = new String[]{tsaURL, tsaUsername, tsaPassword};
    }

    public void setSigningTime(long timeMillis) {
        this.timeMillis = timeMillis;
    }

    public void setSigningTime(Calendar calendar) {
        this.timeMillis = calendar.getTimeInMillis();
    }

    public void setSigningTime(Date date) {
        this.timeMillis = date.getTime();
    }

    protected List<X509CRL> getX509CrlList() throws CRLException {
        CertificateFactory cf = new CertificateFactory();
        List<X509CRL> crlList = new ArrayList<>();
        for (byte[] crl : crls) {
            Collection<X509CRL> crlCol = cf.engineGenerateCRLs(new ByteArrayInputStream(crl));
            crlList.addAll(crlCol);
        }
        return crlList;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public List<String> getHashList() {
        return hashList;
    }

    public void initCerts(List<String> base64Certs) throws Exception {
        try {
            if (base64Certs != null) {
                if (!base64Certs.isEmpty()) {
                    certificates = new ArrayList<>();
                    CertificateFactory cf = new CertificateFactory();
                    for (String cert : base64Certs) {
                        byte[] draw = Base64.decode(cert);
                        ByteArrayInputStream bais = new ByteArrayInputStream(draw);
                        X509Certificate x509Cert = (X509Certificate) cf.engineGenerateCertificate(bais);
                        certificates.add(x509Cert);
                    }
                    if (certificates.isEmpty()) {
                        throw new NullPointerException("Certificate Can't be null");
                    }

                    boolean loadRevocation = rootCertificate;

                    if (form != null) {
                        if (form.isTsa()) {
                            if (tsaData == null) {
                                throw new Exception("Missing TSA data");
                            }
                            tsaSize = 8192;
                        }
                        if (form.isRevocation()) {
                            loadRevocation = true;
                        }
                    }

                    if (loadRevocation) {
                        if (certificates.size() >= 1) {
                            certificates = Utils.getCertPath(certificates.get(0));
                        }

                        if (form != null && form.isRevocation()) {
                            crls = new ArrayList<>();
                            List<X509CRL> crlList = Utils.getCrlFormCerts(certificates);
                            for (X509CRL crl : crlList) {
                                byte[] certBytes = crl.getEncoded();
                                if (certBytes != null) {
                                    ltvSize = ltvSize + certBytes.length;
                                    crls.add(certBytes);
                                }
                            }
                        }
                    }
                }
            }
        } catch (NullPointerException | CertificateException ex) {
            throw new Exception("Can't init Certificates", ex);
        }
    }

    public byte[] createTemporalFile(SigningMethodAsync signingMethod, List<byte[]> dataToBeSign) throws Exception {
        if (signingMethod == null) {
            throw new Exception("Signing Method can't be null");
        }
        if (dataToBeSign == null) {
            throw new Exception("Data to be sign can't be null");
        }
        initCerts(signingMethod.getCert());
        generateHash(dataToBeSign);
        signingMethod.generateTempFile(hashList);
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try ( ObjectOutputStream objectOut = new ObjectOutputStream(baos)) {
                objectOut.writeObject(this);
            }
            return baos.toByteArray();
        } catch (IOException ex) {
            throw new Exception("Can't create temp file :", ex);
        }
    }

    public List<byte[]> sign(SigningMethodSync signingMethod, List<byte[]> dataToBeSign) throws Exception {

        if (signingMethod == null) {
            throw new NullPointerException("SigningMethod is null");
        }

        initCerts(signingMethod.getCert());
        generateHash(dataToBeSign);
        return appendSignautre(signingMethod.sign(hashList));
    }

    public static List<byte[]> sign(SigningMethodAsync signingMethod, byte[] temp) throws Exception {
        try {
            Profile profile;
            try ( ByteArrayInputStream bais = new ByteArrayInputStream(temp)) {
                ObjectInputStream oi = new ObjectInputStream(bais);
                profile = (Profile) oi.readObject();
            }
            return profile.appendSignautre(signingMethod.pack());
        } catch (IOException | ClassNotFoundException ex) {
            throw new Exception("Can't load temp file : ", ex);
        }
    }

    abstract List<byte[]> appendSignautre(List<String> signatureList) throws Exception;

    abstract void generateHash(List<byte[]> dataToBeSign) throws Exception;

    public int getTempDataList() {
        return this.tempDataList.size();
    }
    
    public void setTempDataList(List<byte[]> tempData){
        this.tempDataList = tempData;
    }
    
    public void setOtherList(List<byte[]> otherList){
        this.otherList = otherList;
    }
    
    public void setSignatureID(String id){
        this.signatureId = id;
    }
}
