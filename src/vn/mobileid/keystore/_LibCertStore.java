/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package vn.mobileid.keystore;

import java.io.InputStream;
import java.security.KeyStore;

/**
 *
 * @author minhg
 */
public class _LibCertStore {

    public _LibCertStore() {
    }
    
    public KeyStore getKeyStoreJKS(String storeName, String password) throws Exception{
        InputStream is =  new _LibCertStore().getClass().getResourceAsStream(storeName);        
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(is, password.toCharArray());
        return ks;
    }
    
    public KeyStore getKeyStorePKSC12(String storeName, String password) throws Exception {
        InputStream is =  new _LibCertStore().getClass().getResourceAsStream(storeName);
        KeyStore ks = KeyStore.getInstance("PKSC12");
        ks.load(is, password.toCharArray());
        return ks;
    }
}
