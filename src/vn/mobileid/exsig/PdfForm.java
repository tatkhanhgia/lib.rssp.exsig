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
public enum PdfForm implements Form
{
    B(false ,false, false),
    T(true, false, false),
    LT(true, true, false),
    LTA(true, true, true);

    /**/
    private final boolean tsa, revocation, lta;

    private PdfForm(boolean tsa, boolean revocation, boolean lta) {

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

    @Override
    public String toString()
    {
        return "PAdES-" + this.name();
    }
}
