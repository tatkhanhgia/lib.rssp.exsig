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
interface Form {
    
    public boolean isTsa();
    public boolean isRevocation();
    public boolean isLTA();
}
