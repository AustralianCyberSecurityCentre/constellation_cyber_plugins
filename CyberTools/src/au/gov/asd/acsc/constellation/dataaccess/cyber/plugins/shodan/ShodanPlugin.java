/*
 * Copyright 2010-2019 Australian Signals Directorate
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package au.gov.asd.acsc.constellation.dataaccess.cyber.plugins.shodan;

import au.gov.asd.acsc.constellation.preferences.ACSCPreferenceKeys;
import au.gov.asd.acsc.constellation.schema.cyberschema.concept.CyberConcept;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStore;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStoreUtilities;
import au.gov.asd.tac.constellation.graph.processing.RecordStore;
import au.gov.asd.tac.constellation.graph.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.pluginframework.Plugin;
import au.gov.asd.tac.constellation.pluginframework.PluginException;
import au.gov.asd.tac.constellation.pluginframework.PluginInteraction;
import au.gov.asd.tac.constellation.pluginframework.PluginNotificationLevel;
import au.gov.asd.tac.constellation.pluginframework.parameters.PluginParameter;
import au.gov.asd.tac.constellation.pluginframework.parameters.PluginParameters;
import au.gov.asd.tac.constellation.pluginframework.parameters.types.StringParameterType;
import au.gov.asd.tac.constellation.pluginframework.parameters.types.StringParameterValue;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.ContentConcept;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.SpatialConcept;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.TemporalConcept;
import au.gov.asd.tac.constellation.utilities.temporal.TemporalFormatting;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPlugin;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPluginCoreType;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.prefs.Preferences;
import org.json.JSONArray;
import org.json.JSONObject;

import org.openide.util.NbBundle.Messages;
import org.openide.util.NbPreferences;
import org.openide.util.lookup.ServiceProvider;
import org.openide.util.lookup.ServiceProviders;

@ServiceProviders({
    @ServiceProvider(service = DataAccessPlugin.class)
    ,
    @ServiceProvider(service = Plugin.class)
})
@Messages("ShodanPlugin=Shodan")
public class ShodanPlugin extends RecordStoreQueryPlugin implements DataAccessPlugin {

    @Override
    public String getType() {
        return DataAccessPluginCoreType.ENRICHMENT;
    }

    @Override
    public int getPosition() {
        return Integer.MAX_VALUE - 10;
    }

    @Override
    public String getDescription() {
        return "Shodan";
    }
    
    public static final String ADHOC_PARAMETER = PluginParameter.buildId(ShodanPlugin.class, "adhoc");


    @Override
    public PluginParameters createParameters() {
        final PluginParameters params = new PluginParameters();
        final PluginParameter<StringParameterValue> q = StringParameterType.build(ADHOC_PARAMETER);
        q.setName("Query");
        params.addParameter(q);
        return params;
    }
    
    private void drawSSLCert(JSONObject sslCert, String end, RecordStore results)
    {
        JSONObject fingerprint = sslCert.getJSONObject("fingerprint");
        results.set(end + VisualConcept.VertexAttribute.IDENTIFIER, sslCert.get("serial") );
        results.set(end + AnalyticConcept.VertexAttribute.TYPE, "Certificate");
        results.set(end + CyberConcept.VertexAttribute.SHA256, fingerprint.get("sha256") );
        results.set(end + CyberConcept.VertexAttribute.SHA1, fingerprint.get("sha1") );
        results.set(end + "Serial", sslCert.get("serial") );
        results.set(end + "Expires", TemporalFormatting.parseAsZonedDateTime(sslCert.getString("expires"), DateTimeFormatter.ofPattern("yyyyMMddHHmmssX"), null)  );
        results.set(end + "Issued", TemporalFormatting.parseAsZonedDateTime(sslCert.getString("issued"), DateTimeFormatter.ofPattern("yyyyMMddHHmmssX"), null)  );
        if (sslCert.has("issuer"))
        {
            JSONObject issuer = sslCert.getJSONObject("issuer");
            if (issuer.has("C"))
            {
                results.set(end + "Issuer C", issuer.get("C") );
            }
            if (issuer.has("CN"))
            {
                results.set(end + "Issuer CN", issuer.get("CN") );
            }
            if (issuer.has("L"))
            {
                results.set(end + "Issuer L", issuer.get("L") );
            }
            if (issuer.has("O"))
            {
                results.set(end + "Issuer O", issuer.get("O") );
            }
            if (issuer.has("OU"))
            {
                results.set(end + "Issuer OU", issuer.get("OU") );
            }
            if (issuer.has("ST"))
            {
                results.set(end + "Issuer ST", issuer.get("ST") );
            }
        }
        if (sslCert.has("subject"))
        {
            JSONObject subject = sslCert.getJSONObject("subject");
            if (subject.has("C"))
            {
                results.set(end + "Subject C", subject.get("C") );
            }
            if (subject.has("CN"))
            {
                results.set(end + "Subject CN", subject.get("CN") );
            }
            if (subject.has("L"))
            {
                results.set(end + "Subject L", subject.get("L") );
            }
            if (subject.has("O"))
            {
                results.set(end + "Subject O", subject.get("O") );
            }
            if (subject.has("OU"))
            {
                results.set(end + "Subject OU", subject.get("OU") );
            }
            if (subject.has("ST"))
            {
                results.set(end + "Subject ST", subject.get("ST") );
            }
        }
        
    }
    
    private void drawResults(JSONObject b, String serviceName, RecordStore results)
    {
        JSONObject shodan = b.getJSONObject("_shodan");
        String ip = b.getString("ip_str");
        String type = "";
        if (ip != null)
        {
            type = AnalyticConcept.VertexType.IP_ADDRESS.getName();
            if (ip.contains("."))
            {
                type = AnalyticConcept.VertexType.IPV4.getName();
            }
            else if (ip.contains(":"))
            {
                type = AnalyticConcept.VertexType.IPV6.getName();
            }
        }
        
        for (String key : b.keySet())
        {
            List<String> ignores = Arrays.asList("_shodan", "timestamp","data","hash","transport","asn","ip_str","ip","isp","domains","cpe","port","org","product","version","os","info","link");
            if ( ignores.contains(key))
            {
                // do nothing
            }
            else if (key.equalsIgnoreCase("tags"))
            {
                JSONArray tags = b.getJSONArray(key);
                for (Object t : tags)
                {
                    results.add();
                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                    results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, (String)t);
                    results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, "Tag");
                }
                        
            }
            else if (key.equalsIgnoreCase("location"))
            {
                results.add();
                results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
                results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                
                JSONObject location = b.getJSONObject("location");
                if (location.has("country_name") && location.get("country_name") != null)
                {
                    results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.COUNTRY, location.get("country_name"));
                }
                if (location.has("city") && location.get("city") != null)
                {
                    results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.CITY, location.get("city"));
                }
                if (location.has("latitude") && location.get("latitude") != null)
                {
                    results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.LATITUDE, location.get("latitude"));
                }
                if (location.has("longitude") && location.get("longitude") != null)
                {
                    results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.LONGITUDE, location.get("longitude"));
                }
                if (location.has("postal_code") && location.get("postal_code") != null)
                {
                    results.set(GraphRecordStoreUtilities.SOURCE + "Postal Code", location.get("postal_code"));
                }
                if (location.has("region_code") && location.get("region_code") != null)
                {
                    results.set(GraphRecordStoreUtilities.SOURCE + "Region", location.get("region_code"));
                }
            }
            else if (key.equalsIgnoreCase("vulns"))
            {
                JSONObject vulns = b.getJSONObject("vulns");
                drawVulnerabilities(vulns, serviceName, results);  
            }
            else if (key.equalsIgnoreCase("http"))
            {
                JSONObject http = b.getJSONObject("http");
                results.add();
                results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, serviceName);
                results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, "Service");

                results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, http.getString("host"));
                results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);


                results.add();
                results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
                results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, serviceName);
                results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.SERVICE);

                results.set(GraphRecordStoreUtilities.TRANSACTION + "Headers", b.get("data"));
                results.set(GraphRecordStoreUtilities.TRANSACTION + ContentConcept.VertexAttribute.CONTENT, http.get("html"));
                results.set(GraphRecordStoreUtilities.TRANSACTION + ContentConcept.VertexAttribute.TITLE, http.get("title"));
                results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.DATETIME, TemporalFormatting.completeZonedDateTimeString((String)b.get("timestamp")));
                results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, shodan.getString("module"));
                results.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.VertexAttribute.IDENTIFIER, shodan.getString("id"));
                results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.VertexAttribute.SOURCE, "Shodan");
                if (http.has("location"))
                {
                    results.set(GraphRecordStoreUtilities.TRANSACTION + "Location", http.getString("location"));
                }
            }
            else if (key.equalsIgnoreCase("hostnames"))
            {
                JSONArray hostnames = b.getJSONArray("hostnames");
                for (Object o : hostnames)
                {
                    results.add();
                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, serviceName);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, "Service");

                    results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, (String)o);
                    results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);
                }
            }
            else if (key.equalsIgnoreCase("ssl"))
            {
                JSONObject ssl = b.getJSONObject("ssl");
                if (ssl.has("cert"))
                {
                    results.add();
                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                    results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, serviceName);
                    results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.SERVICE);

                    results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.DATETIME, TemporalFormatting.completeZonedDateTimeString((String)b.get("timestamp")));
                    results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, shodan.getString("module"));
                    results.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.VertexAttribute.IDENTIFIER, shodan.get("id"));
                    results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.VertexAttribute.SOURCE, "Shodan");

                    JSONObject cert = ssl.getJSONObject("cert");
                    results.add();
                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, serviceName);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, "Service");
                    drawSSLCert(cert, GraphRecordStoreUtilities.DESTINATION, results);
                }
            }
            else if (key.equalsIgnoreCase("dns"))
            {
                JSONObject dns = b.getJSONObject("dns");
            
                results.add();
                results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, serviceName);
                results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, "Service");
                if (dns.has("resolver_hostname") && dns.get("resolver_hostname") != null)
                {
                    results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, dns.get("resolver_hostname"));
                    results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);
                }
            }
            else if (key.equalsIgnoreCase("ssh"))
            {
                JSONObject ssh = (JSONObject)b.get("ssh");
                results.set(GraphRecordStoreUtilities.TRANSACTION + "Cipher", ssh.get("cipher"));
                results.set(GraphRecordStoreUtilities.TRANSACTION + "Hassh", ssh.get("hassh"));
                results.set(GraphRecordStoreUtilities.TRANSACTION + "Key", ssh.get("key"));
                results.set(GraphRecordStoreUtilities.TRANSACTION + "SSH Type", ssh.get("type"));           
            }
            else if (key.equalsIgnoreCase("ftp"))
            {
                //TODO if needed.
            }
            else 
            {
                System.out.println("UNMAPPED KEY IS " + key);
                System.out.println(b.get(key));
            }
        }

    }
    
    private void drawVulnerabilities(JSONObject vulns, String serviceName, RecordStore results)
    {
       for (Object k : vulns.keySet())
       {
            String cveName = (String)k;
            JSONObject cve = vulns.getJSONObject(cveName);
           
            results.add();
            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, serviceName);
            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.SERVICE);

            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, cveName);
            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.CVE);
            JSONArray refs = cve.getJSONArray("references");
            ArrayList<String> rs = new ArrayList<>();
            for (Object a : refs)
            {
                rs.add((String)a);
            }
            
            results.set(GraphRecordStoreUtilities.DESTINATION + "References", String.join("\n", rs));
            results.set(GraphRecordStoreUtilities.DESTINATION + "Summary", cve.get("summary"));
            results.set(GraphRecordStoreUtilities.DESTINATION + "CVSS", cve.get("cvss"));
            results.set(GraphRecordStoreUtilities.DESTINATION + "Verified", cve.get("verified"));
       }
    }
    
    
    
    private void runQuery(String query, ShodanClient client, RecordStore results, PluginInteraction interaction)
    {
        Integer resultCount = client.searchCount(query, interaction);
                
        if (resultCount != null && resultCount > 0 )
        {
            JSONObject res = client.search(query, interaction);
            if (res != null)
            {
                JSONArray matches = res.getJSONArray("matches");
                for (Object o : matches)
                {
                    JSONObject p = (JSONObject)o;
                    String ip = p.getString("ip_str");
                    String type = "";
                    if (ip != null)
                    {
                        type = AnalyticConcept.VertexType.IP_ADDRESS.getName();
                        if (ip.contains("."))
                        {
                            type = AnalyticConcept.VertexType.IPV4.getName();
                        }
                        else if (ip.contains(":"))
                        {
                            type = AnalyticConcept.VertexType.IPV6.getName();
                        }
                    }
                    
                    results.add();
                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                    if (p.has("isp"))
                    {
                        results.set(GraphRecordStoreUtilities.SOURCE + "ISP", p.get("isp"));
                    }
                    if (p.has("org"))
                    {
                        results.set(GraphRecordStoreUtilities.SOURCE + "Organisation", p.get("org"));
                    }
                       
                    JSONObject shodan = p.getJSONObject("_shodan");

                    String module = shodan.getString("module");
                    String version = "";
                    if (p.has("version"))
                    {
                        version = p.getString("version");
                    }
                    String product = "";
                    if (p.has("product"))
                    {
                        product = p.getString("product");
                    }
                    String port = "";
                    if (p.has("port"))
                    {
                        port = Integer.toString(p.getInt("port"));
                    }
                    String transport = "";
                    if (p.has("transport"))
                    {
                        transport = p.getString("transport");
                    }
                    
                    String serviceName = String.format("%s-%s-%s %s %s", port, transport, module, product, version ).trim();
                    
                    results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, serviceName);
                    results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.SERVICE);
                    results.set(GraphRecordStoreUtilities.DESTINATION + "Product", product);
                    results.set(GraphRecordStoreUtilities.DESTINATION + "Version", version);
                    results.set(GraphRecordStoreUtilities.DESTINATION + "Module", module);
                    results.set(GraphRecordStoreUtilities.DESTINATION + "JSON", p.toString(4));
                    results.set(GraphRecordStoreUtilities.DESTINATION + "Port", port);
                    results.set(GraphRecordStoreUtilities.DESTINATION + "Transport", transport);
                    
                    results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, module);
                    results.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.VertexAttribute.IDENTIFIER, shodan.get("id"));
                    results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.VertexAttribute.SOURCE, "Shodan");
                    results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.DATETIME, TemporalFormatting.completeZonedDateTimeString((String)p.get("timestamp")));

                    drawResults(p, serviceName, results);

                }
                    
                
            }
        }
    }

    @Override
    protected RecordStore query(final RecordStore query, final PluginInteraction interaction, final PluginParameters parameters) throws PluginException {

        final RecordStore results = new GraphRecordStore();

        String APIKey = null;
        
        Preferences prefs = NbPreferences.forModule(ACSCPreferenceKeys.class);

        APIKey = prefs.get(ACSCPreferenceKeys.SHODAN_API_KEY, "");
        if (APIKey == null || APIKey.isEmpty())
        {
            interaction.notify(PluginNotificationLevel.FATAL, "The API key has not been set.\nPlease update these at Setup > Options > CONSTELLATION > ACSC > Shodan");
            return results;
        }
        
        ShodanClient client = new ShodanClient(APIKey);
        
        int credits = client.getCredits(interaction);
        System.out.println(credits);
        
        final Map<String, PluginParameter<?>> params = parameters.getParameters();
        String q = params.get(ADHOC_PARAMETER).getStringValue();
        
        if (q != null && !q.isEmpty())
        {
            runQuery(q, client, results, interaction);
        }
        else
        {
            if (query.size() == 0) {
                return results;
            }

        query.reset();
            while (query.next()) {
                String identifier = query.get(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER);
                String type = query.get(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE);

                if (type.equals(AnalyticConcept.VertexType.IPV4.toString())) 
                {
                    String search = String.format("ip:%s",identifier);

                    runQuery(search, client, results, interaction);


                }
                else if (type.equals(AnalyticConcept.VertexType.HOST_NAME.toString())) 
                {

                }


            }
        }

        return results;
    }

}
