/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package vn.mobileid.exsig;

import java.util.List;
/**
 *
 * @author minhg
 */
public interface SigningMethodSync {
    public List<String> sign(List<String> hashList) throws Exception;
    public List<String> getCert() throws Exception;
}
