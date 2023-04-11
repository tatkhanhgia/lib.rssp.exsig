/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package vn.mobileid.exsig;

/**
 *
 * @author Minhgalc
 */
public enum Prefix {
    ORGANIZATION("ORGANIZATION"),
    SIGNBY("SIGNBY"),
    REASON("REASON"),
    LOCATION("LOCATION"),
    DATE("DATE"),
    EMAIL("EMAIL"),                
    PHONE("PHONE"); 

    private final String value;
    
    private Prefix(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

}
