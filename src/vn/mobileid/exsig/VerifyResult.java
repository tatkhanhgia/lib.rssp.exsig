/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package vn.mobileid.exsig;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 *
 * @author minhg
 */
public class VerifyResult {

    private String id;
    private String signingForm;
    private X509Certificate signingCertificate;
    private final String algorithm;
    private final String signingTimes;
    private final boolean SignatureValid;

    public String getId() {
        return id;
    }

    public void setSigningForm(String signingForm) {
        this.signingForm = signingForm;
    }

    public String getSigningForm() {
        return signingForm;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getSigningTimes() {
        return signingTimes;
    }

    public X509Certificate getSigningCertificate() {
        return signingCertificate;
    }

    public boolean isSignatureValid() {
        return SignatureValid;
    }

    public VerifyResult(
            String id,
            String signingForm,
            X509Certificate signingCertificate,
            String algorithm,
            String signingTimes,
            boolean SignatureValid) {
        this.id = id;
        this.signingForm = signingForm;
        this.signingCertificate = signingCertificate;
        this.algorithm = algorithm;
        this.signingTimes = signingTimes;
        this.SignatureValid = SignatureValid;
    }

    public void showResults() {
        System.out.println("    Signature Valid : " + SignatureValid);
        System.out.println("    Signature ID : " + id);
        System.out.println("    Signing Form : " + signingForm);
        if (signingCertificate != null) {
            System.out.println("    Signing Certificate : " + signingCertificate.getSubjectDN().getName());
        } else {
            System.out.println("    Signing Certificate : " + signingCertificate);
        }
        System.out.println("    Algorithms : " + algorithm);
        System.out.println("    Signing Time : " + signingTimes);
        if (!SignatureValid) {
            System.out.println("##########################################################");
        }
        System.out.println();

    }

}
