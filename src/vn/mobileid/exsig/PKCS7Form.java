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
public enum PKCS7Form implements Form
{
    BES(false ,false, false),
    T(true, false, false),
    LT(true, true, false);

    /**/
    private final boolean tsa, revocation, lta;

    private PKCS7Form(boolean tsa, boolean revocation, boolean lta) {
        this.tsa = tsa;
        this.revocation = revocation;
        this.lta = lta;
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
    public boolean isLTA() {
        return lta;
    }
    
}
