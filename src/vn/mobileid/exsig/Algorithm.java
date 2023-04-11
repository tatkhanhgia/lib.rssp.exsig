/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package vn.mobileid.exsig;

public enum Algorithm {
    SHA1("SHA-1", "1.3.14.3.2.26"),
    SHA256("SHA-256", "2.16.840.1.101.3.4.2.1"),
    SHA384("SHA-384", "2.16.840.1.101.3.4.2.2"),
    SHA512("SHA-512", "2.16.840.1.101.3.4.2.3");
     
    private final String value;
    private final String oid;


    private Algorithm(String value, String oid) {
        this.value = value;
        this.oid = oid;
    }

    public String getOid() {
        return oid;
    }
    
    public String getValue() {
        return value;
    }

   

}
