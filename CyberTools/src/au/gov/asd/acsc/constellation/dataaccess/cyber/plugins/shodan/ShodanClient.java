/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package au.gov.asd.acsc.constellation.dataaccess.cyber.plugins.shodan;

import au.gov.asd.tac.constellation.pluginframework.PluginInteraction;
import au.gov.asd.tac.constellation.pluginframework.PluginNotificationLevel;
import au.gov.asd.tac.constellation.security.proxy.ConstellationHttpProxySelector;
import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import org.apache.http.HttpHost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.openide.util.Exceptions;

/**
 *
 * @author craig
 */
public class ShodanClient 
{
    String apiKey = null;
    String apiBase = "https://api.shodan.io";
    
    private JSONObject query(String query, PluginInteraction interaction)
    {
        int page = 0;
        JSONObject res = null;
        while (true)
        {
            page++;
            JSONObject out = query(query, page, interaction);
            if (out != null)
            {
                if (out.has("matches"))
                {

                    JSONArray arr = out.getJSONArray("matches");

                    if (res == null)
                    {
                        res = out;
                    }
                    else
                    {    
                        
                        for (Object o : arr)
                        {
                            res.getJSONArray("matches").put(o);
                        }
                    }

                    if (arr.length() < 100 || out.getInt("total") < 100)
                    {
                        break;
                    }
                }
                else
                {
                    return out;
                }
            }
               
        }
                
        return res;
        
    }
    
    private JSONObject query(String query, int page, PluginInteraction interaction)
    {
        JSONObject result = null;
        String c = "";
        if (query.contains("?"))
        {
            c = String.format("&key=%s",apiKey);
        }
        else
        {
            c = String.format("?key=%s",apiKey);
        }
        c += String.format("&page=%s", page);
        
        try {
            ProxySelector sel = ConstellationHttpProxySelector.getDefault();
            List<Proxy> proxies = sel.select(new URI(query));
            for (Proxy proxy : proxies) {
                HttpClientBuilder clientBuilder = HttpClients.custom();
                if (proxy.type() != Proxy.Type.DIRECT) {
                    String h = proxy.address().toString();
                    String addr = null;
                    Integer port = null;
                    if (h.contains(":")) {
                        addr = h.split(":")[0];
                        addr = addr.split("/")[0];
                        port = Integer.parseInt(h.split(":")[1]);
                    } else {
                        addr = h;
                    }
                    if (port != null) {
                        clientBuilder.setProxy(new HttpHost(addr, port));
                    } else {
                        clientBuilder.setProxy(new HttpHost(addr));
                    }
                }
                CloseableHttpClient client = clientBuilder.build();
                HttpGet get = new HttpGet(query + c);
                System.out.println("Running query on " + query+c);
                CloseableHttpResponse resp;
                try {
                    resp = client.execute(get);
                } catch (IOException ex) {
                    if (interaction != null) {
                        interaction.notify(PluginNotificationLevel.FATAL, "Failed to query the Shodan web service " + ex.getMessage());
                    }
                    return null;
                }

                try {
                    if (resp.getStatusLine().getStatusCode() == 200) {
                        String answer = EntityUtils.toString(resp.getEntity());
                        result = new JSONObject(answer);
                
                    } 
                    else {
                        return null;
                    }
                } catch (IOException ex) {
                    if (interaction != null) {
                        interaction.notify(PluginNotificationLevel.FATAL, "Could not read from the Shodan web service.");
                    }
                    return null;
                } catch (org.apache.http.ParseException ex) {
                    Exceptions.printStackTrace(ex);
                    return null;
                }
                break;
            }

        } catch (URISyntaxException ex) {
            Exceptions.printStackTrace(ex);
        }
        
        return result;
    }
    
    public ShodanClient(String apiKey)
    {
        this.apiKey = apiKey;
    }
    
    public JSONObject search(String query, PluginInteraction interaction)
    {
        JSONObject o = null;
        
        Object res = query(String.format("%s%s?query=%s", apiBase,"/shodan/host/search", query), interaction);
        if (res instanceof JSONObject)
        {
            JSONObject p = (JSONObject)res;
            return p;
        }
        return o;
    }
    
    public Integer searchCount(String query, PluginInteraction interaction)
    {
        Integer o = null;
        
        Object countObj = query(String.format("%s%s?query=%s", apiBase,"/shodan/host/count", query), interaction);
        if (countObj instanceof JSONObject)
        {
            JSONObject p = (JSONObject)countObj;
            Integer l = p.getInt("total");
            return l;
        }
        return o;
    }
    
    public Integer getCredits(PluginInteraction interaction)
    {
        Object o = query(String.format("%s%s", apiBase,"/account/profile"), interaction);
        if (o instanceof JSONObject)
        {
            JSONObject p = (JSONObject)o;
            Integer l = p.getInt("credits");
            return l;
        }
        else
        {
            //error
        }
        return -1;   
            
    }
    
}
