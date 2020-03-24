/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package au.gov.asd.acsc.constellation.dataaccess.cyber.plugins.virustotal;

/**
 *
 * @author craig
 */
public class Hash {
    
    private String md5;
    private String ssdeep;
    private String vhash;
    private String imphash;

    public String getMd5() {
        return md5;
    }

    public void setMd5(String md5) {
        this.md5 = md5;
    }

    public String getSsdeep() {
        return ssdeep;
    }

    public void setSsdeep(String ssdeep) {
        this.ssdeep = ssdeep;
    }

    public String getVhash() {
        return vhash;
    }

    public void setVhash(String vhash) {
        this.vhash = vhash;
    }

    public String getImphash() {
        return imphash;
    }

    public void setImphash(String imphash) {
        this.imphash = imphash;
    }
    
    
}
