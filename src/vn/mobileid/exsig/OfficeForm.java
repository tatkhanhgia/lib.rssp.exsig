package vn.mobileid.exsig;


public enum OfficeForm implements Form
{
    DSIG(false, false, false),
    EPES(false, false, false),
    T(true, false, false),
    X_L(true, true, false);
    
    private final boolean tsa, revocation, lta;

    private OfficeForm(boolean tsa, boolean revocation, boolean lta) {
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
    public String toString()
    {
        return this.name();
    }

    @Override
    public boolean isLTA() {
        return lta;
    }
}