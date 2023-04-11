/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package vn.mobileid.exsig;

/**
 *
 * @author minhg
 */
public enum CAdESForm implements Form
{
    BES("BES", "Basic electronic signature", false ,false),
    T("T", "Electronic signature with time", true, false),
    X_L("X-L", "Extended long electronic signatures with time", true, true);

    /**/
    private final String alias, fullName;
    private final boolean tsa, revocation;

    private CAdESForm(String alias, String fullName, boolean tsa, boolean revocation) {
        this.alias = alias;
        this.fullName = fullName;
        this.tsa = tsa;
        this.revocation = revocation;
    }

    @Override
    public boolean isTsa() {
        return tsa;
    }

    @Override
    public boolean isRevocation() {
        return revocation;
    }
    
    

    @Override
    public String toString()
    {
        return "CAdES-" + alias;
    }

    @Override
    public boolean isLTA() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
