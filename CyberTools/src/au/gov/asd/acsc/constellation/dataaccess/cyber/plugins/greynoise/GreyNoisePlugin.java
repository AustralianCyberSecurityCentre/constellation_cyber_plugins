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
package au.gov.asd.acsc.constellation.dataaccess.cyber.plugins.greynoise;

import au.gov.asd.acsc.constellation.dataaccess.cyber.plugins.maxmind.MaxmindConcept;
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
import au.gov.asd.tac.constellation.pluginframework.parameters.types.BooleanParameterType;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.SpatialConcept;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.TemporalConcept;
import au.gov.asd.tac.constellation.security.proxy.ConstellationHttpProxySelector;
import au.gov.asd.tac.constellation.utilities.temporal.TemporalFormatting;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPlugin;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPluginCoreType;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.prefs.Preferences;
import org.apache.http.HttpHost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.openide.util.Exceptions;
import org.openide.util.NbBundle.Messages;
import org.openide.util.NbPreferences;

import org.openide.util.lookup.ServiceProvider;
import org.openide.util.lookup.ServiceProviders;
import org.python.google.common.collect.Lists;

@ServiceProviders({
    @ServiceProvider(service = DataAccessPlugin.class)
    ,
    @ServiceProvider(service = Plugin.class)
})
@Messages("GreyNoisePlugin=GreyNoise Enrichment")
public class GreyNoisePlugin extends RecordStoreQueryPlugin implements DataAccessPlugin {

    public static final String DETAILED_PARAMETER = PluginParameter.buildId(GreyNoisePlugin.class, "detailedContext");

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
        return "Query GreyNoise API";
    }

    @Override
    public PluginParameters createParameters() {
        final PluginParameters params = new PluginParameters();
        
        final PluginParameter<BooleanParameterType.BooleanParameterValue> detailed = BooleanParameterType.build(DETAILED_PARAMETER);
        detailed.setName("Detailed Context");
        detailed.setDescription("WARNING: this will use 1 API call per IP");
        detailed.setBooleanValue(false);
        params.addParameter(detailed);
        
        return params;
    }



    @Override
    protected RecordStore query(final RecordStore query, final PluginInteraction interaction, final PluginParameters parameters) throws PluginException {

        final RecordStore results = new GraphRecordStore();
        final Preferences prefs = NbPreferences.forModule(ACSCPreferenceKeys.class);
        final String apiKey = prefs.get(ACSCPreferenceKeys.GREYNOISE_API_KEY, null);
        

        if (apiKey == null || apiKey.isEmpty() ) {
            interaction.notify(PluginNotificationLevel.FATAL, "The API key has not been set.\nPlease update these at Setup > Options > CONSTELLATION > ACSC > GreyNoise");
            return results;
        }

        if (query.size() == 0) {
            return results;
        }
       
        
        query.reset();
        final Map<String, PluginParameter<?>> params = parameters.getParameters();
        boolean detailed = params.get(DETAILED_PARAMETER).getBooleanValue();
        
        HashSet<String> ips = new HashSet<>();
        
        while (query.next()) {
            String identifier = query.get(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER);
            String type = query.get(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE);
            if (type.equals(AnalyticConcept.VertexType.IPV4.toString())
                    || type.equals(AnalyticConcept.VertexType.IPV6.toString())
                    || type.equals(AnalyticConcept.VertexType.IP_ADDRESS.toString())) {
                ips.add(identifier);
            }
        }
        
        if (!detailed)
        {
            List<List<String>> partitions = Lists.partition(new ArrayList<>(ips), 1000);
            JSONParser parser = new JSONParser();
            ProxySelector ps = ConstellationHttpProxySelector.getDefault();
            try {
                List<Proxy> proxies = ps.select(new URI("https://api.greynoise.io"));
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
                    for (List<String> partition : partitions)
                    {
                        String q = String.format("https://api.greynoise.io/v2/noise/multi/quick?ips=%s", String.join(",", partition));
                        HttpGet get = new HttpGet(q);
                        get.addHeader("key", apiKey);
                        get.addHeader("Accept","application/json");

                        CloseableHttpResponse resp;
                        try {
                            resp = client.execute(get);
                        } catch (IOException ex) {
                            if (interaction != null) {
                                interaction.notify(PluginNotificationLevel.FATAL, "Failed to query the VirusTotal web service " + ex.getMessage());
                            }
                            ex.printStackTrace();
                            return null;
                        }

                        HashMap<String,String> codeMappings = new HashMap<>();
                        codeMappings.put("0x00","The IP has never been observed scanning the Internet");
                        codeMappings.put("0x01","The IP has been observed by the GreyNoise sensor network");
                        codeMappings.put("0x02","The IP has been observed scanning the GreyNoise sensor network, but has not completed a full connection, meaning this can be spoofed");
                        codeMappings.put("0x03","The IP is adjacent to another host that has been directly observed by the GreyNoise sensor network");
                        codeMappings.put("0x04","Reserved");
                        codeMappings.put("0x05","This IP is commonly spoofed in Internet-scan activity");
                        codeMappings.put("0x06","This IP has been observed as noise, but this host belongs to a cloud provider where IPs can be cycled frequently");
                        codeMappings.put("0x07","This IP is invalid");
                        codeMappings.put("0x08","This IP was classified as noise, but has not been observed engaging in Internet-wide scans or attacks in over 60 days");

                        try {
                            if (resp.getStatusLine().getStatusCode() == 200) {
                                String answer = EntityUtils.toString(resp.getEntity());

                                try {
                                    Object obj = parser.parse(answer);
                                    JSONArray res = (JSONArray)obj;
                                    for (Object o : res)
                                    {
                                        JSONObject r = (JSONObject)o;
                                        String ip = (String)r.get("ip");
                                        Boolean isNoise = (Boolean)r.get("noise");
                                        String code = (String)r.get("code");

                                        results.add();
                                        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
                                        if (ip.contains("."))
                                        {
                                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.IPV4);
                                        }
                                        else if (ip.contains(":"))
                                        {
                                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.IPV6);
                                        }
                                        else
                                        {
                                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.IP_ADDRESS);
                                        }
                                        results.set(GraphRecordStoreUtilities.SOURCE + GreyNoiseConcept.VertexAttribute.IS_NOISE, isNoise);

                                        if (code != null && codeMappings.containsKey(code))
                                        {
                                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.COMMENT, codeMappings.get(code));
                                        }

                                    }
                                } catch (ParseException ex) {
                                    if (interaction != null) {
                                        interaction.notify(PluginNotificationLevel.FATAL, "Could not parse the GreyNoise web service response");
                                    }
                                    return null;
                                }
                            } 
                            else if (resp.getStatusLine().getStatusCode() == 400)
                            {
                                interaction.notify(PluginNotificationLevel.FATAL, "Bad API request.");

                                return results;
                            }
                            else if (resp.getStatusLine().getStatusCode() == 401)
                            {
                                // unauthorised
                                interaction.notify(PluginNotificationLevel.FATAL, "Unauthorised, please check API key.");

                                return results;
                            }
                            else if (resp.getStatusLine().getStatusCode() == 429)
                            {
                                // unauthorised
                                interaction.notify(PluginNotificationLevel.WARNING, "To many requests, you have hit the rate limit.");
                                // do retry here.

                            }
                            else {
                                interaction.notify(PluginNotificationLevel.FATAL, "Could not access the GreyNoise web service error code " + resp.getStatusLine().getStatusCode());
                                return results;
                            }
                        } catch (IOException ex) {
                            interaction.notify(PluginNotificationLevel.FATAL, "Could not read from the GreyNoise web service.");

                            return results;
                        } catch (org.apache.http.ParseException ex) {
                            Exceptions.printStackTrace(ex);
                            return results;
                        }
                    }
                    break;
                }
            } catch (URISyntaxException ex) {
                Exceptions.printStackTrace(ex);
            }
        }
        else
        {
            JSONParser parser = new JSONParser();
            ProxySelector ps = ConstellationHttpProxySelector.getDefault();
            try {
                List<Proxy> proxies = ps.select(new URI("https://api.greynoise.io"));
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
                    for (String ip : ips)
                    {
                        String q = String.format("https://api.greynoise.io/v2/noise/context/%s", ip);
                        HttpGet get = new HttpGet(q);
                        get.addHeader("key", apiKey);
                        get.addHeader("Accept","application/json");

                        CloseableHttpResponse resp;
                        try {
                            resp = client.execute(get);
                        } catch (IOException ex) {
                            if (interaction != null) {
                                interaction.notify(PluginNotificationLevel.FATAL, "Failed to query the GreyNoise web service " + ex.getMessage());
                            }
                            ex.printStackTrace();
                            return null;
                        }

                        try {
                            if (resp.getStatusLine().getStatusCode() == 200) {
                                String answer = EntityUtils.toString(resp.getEntity());

                                try {
                                    Object obj = parser.parse(answer);

                                    JSONObject r = (JSONObject)obj;
                                    String ip1 = (String)r.get("ip");
                                    String classification = (String)r.get("classification");
                                    String firstSeen = (String)r.get("first_seen");
                                    String lastSeen = (String)r.get("last_seen");
                                    String actor = (String)r.get("actor");
                                    JSONArray tags = (JSONArray)r.get("tags");
                                    JSONObject metadata = (JSONObject)r.get("metadata");
                                    JSONObject rawData = (JSONObject)r.get("raw_data");
                                    
                                    JSONArray ja3s = (JSONArray)rawData.get("ja3");

                                    results.add();
                                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip1);
                                    String type = null;
                                    if (ip.contains("."))
                                    {
                                        type = AnalyticConcept.VertexType.IPV4.toString();
                                    }
                                    else if (ip.contains(":"))
                                    {
                                        type = AnalyticConcept.VertexType.IPV6.toString();
                                    }
                                    else
                                    {
                                        type = AnalyticConcept.VertexType.IP_ADDRESS.toString();
                                    }
                                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                                    if (classification != null && !classification.isEmpty())
                                    {
                                        results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.CLASSIFICATION, classification);
                                    }
                                    if (firstSeen != null && !firstSeen.isEmpty())
                                    {
                                        results.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.FIRST_SEEN, TemporalFormatting.completeZonedDateTimeString(firstSeen));
                                    }
                                    if (lastSeen != null && !lastSeen.isEmpty())
                                    {
                                        results.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.LAST_SEEN, TemporalFormatting.completeZonedDateTimeString(lastSeen));
                                    }
                                    if (actor != null && !actor.isEmpty())
                                    {
                                        results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.ACTOR, actor);
                                    }
                                    if (tags != null )
                                    {
                                        results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.TAGS, String.join("\n", tags));
                                    }
                                    if (metadata != null )
                                    {
                                        String country = (String)metadata.get("country");
                                        String city = (String)metadata.get("city");
                                        String organisation = (String)metadata.get("organization");
                                        String rdns = (String)metadata.get("rdns");
                                        Boolean tor = (Boolean)metadata.get("tor");
                                        String os = (String)metadata.get("os");
                                        String category = (String)metadata.get("Category");
                                        if (country != null && !country.isEmpty())
                                        {
                                            results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.COUNTRY, country);
                                        }
                                        if (city != null && !city.isEmpty())
                                        {
                                            results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.CITY, city);
                                        }
                                        if (organisation != null && !organisation.isEmpty())
                                        {
                                            results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.ORGANISATION, organisation);
                                        }
                                        if (tor != null )
                                        {
                                            results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.IS_TOR_EXIT_NODE, tor);
                                        }
                                        if (rdns != null && !rdns.isEmpty())
                                        {
                                            results.set(GraphRecordStoreUtilities.SOURCE + "rDNS", rdns);
                                        }
                                        if (os != null && !os.isEmpty())
                                        {
                                            results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.OPERATING_SYSTEM, os);
                                        }
                                        if (category != null && !category.isEmpty())
                                        {
                                            results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.CATEGORY, category);
                                        }

                                        results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.TAGS, String.join("\n", tags));
                                    }
                                    if (ja3s != null )
                                    {
                                        for (Object o1 : ja3s)
                                        {
                                            JSONObject ja3 = (JSONObject)o1;
                                            String fingerprint = (String)ja3.get("fingerprint");
                                            Long port = (Long)ja3.get("port");
                                            results.add();
                                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);  
                                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, fingerprint);  
                                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.JA3);
                                            results.set(GraphRecordStoreUtilities.TRANSACTION + CyberConcept.TransactionAttribute.DST_PORTS, port);

                                        }
                                    }
                                    
                                } catch (ParseException ex) {
                                    Exceptions.printStackTrace(ex);
                                }
                            }
                            else if (resp.getStatusLine().getStatusCode() == 400)
                            {
                                interaction.notify(PluginNotificationLevel.FATAL, "Bad API request.");

                                return results;
                            }
                            else if (resp.getStatusLine().getStatusCode() == 401)
                            {
                                // unauthorised
                                interaction.notify(PluginNotificationLevel.FATAL, "Unauthorised, please check API key.");

                                return results;
                            }
                            else if (resp.getStatusLine().getStatusCode() == 429)
                            {
                                // unauthorised
                                interaction.notify(PluginNotificationLevel.WARNING, "To many requests, you have hit the rate limit.");
                                // do retry here.

                            }
                            else {
                                interaction.notify(PluginNotificationLevel.FATAL, "Could not access the GreyNoise web service error code " + resp.getStatusLine().getStatusCode());
                                return results;
                            }
                        } catch (IOException ex) {
                            Exceptions.printStackTrace(ex);
                        } catch (org.apache.http.ParseException ex) {
                            Exceptions.printStackTrace(ex);
                        }
                    }
                }
            } catch (URISyntaxException ex) {
                Exceptions.printStackTrace(ex);
            }
            
        }
        

        return results;
    }

}
