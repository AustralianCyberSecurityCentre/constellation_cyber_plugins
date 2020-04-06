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
package au.gov.asd.acsc.constellation.dataaccess.cyber.plugins.virustotal;

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
import au.gov.asd.tac.constellation.pluginframework.parameters.types.MultiChoiceParameterType;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.SpatialConcept;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.TemporalConcept;
import au.gov.asd.tac.constellation.security.proxy.ConstellationHttpProxySelector;
import au.gov.asd.tac.constellation.utilities.temporal.TemporalFormatting;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPlugin;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPluginCoreType;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import com.google.common.net.UrlEscapers;
import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
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

@ServiceProviders({
    @ServiceProvider(service = DataAccessPlugin.class)
    ,
    @ServiceProvider(service = Plugin.class)
})
@Messages("VirusTotalPlugin=VirusTotal")
public class VirusTotalPlugin extends RecordStoreQueryPlugin implements DataAccessPlugin {

    private String VT_URL = null;
    private String VT_API_KEY = null;
    boolean isEnabled = true;

    public VirusTotalPlugin() {

    }

    @Override
    public boolean isEnabled() {
        return isEnabled;
    }

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
        return "VirusTotal";
    }

    public static final String SHOW_AV_RESULTS_PARAMETER = PluginParameter.buildId(VirusTotalPlugin.class, "showAVResults");
    public static final String HASH_PIVOTS_PARAMETER_ID = PluginParameter.buildId(VirusTotalPlugin.class, "hashPivots");

    @Override
    public PluginParameters createParameters() {
        final PluginParameters params = new PluginParameters();

        final PluginParameter<BooleanParameterType.BooleanParameterValue> showAVResults = BooleanParameterType.build(SHOW_AV_RESULTS_PARAMETER);
        showAVResults.setName("Show AntiVirus Results");
        showAVResults.setDescription("Show AntiVirus Results");
        showAVResults.setBooleanValue(false);
        params.addParameter(showAVResults);

        final PluginParameter hashPivotOptions = MultiChoiceParameterType.build(HASH_PIVOTS_PARAMETER_ID);
        hashPivotOptions.setName("Pivot on Hash");
        ArrayList<String> hashPivots = new ArrayList<>();
        
        //hashPivots.add("ssdeep");
        hashPivots.add("imphash");
        hashPivots.add("vHash");
        hashPivots.add("similar to");
        hashPivots.sort(null);
        
        MultiChoiceParameterType.setOptions(hashPivotOptions, hashPivots);
        
        MultiChoiceParameterType.setChoices(hashPivotOptions, new ArrayList<String>());
        params.addParameter(hashPivotOptions);

        return params;
    }

    private Object getQuery(String query, PluginInteraction interaction)
    {
        return getQuery(query, interaction, null);
    }
    
    private Object getQuery(String query, PluginInteraction interaction, String cursor) {
        JSONParser parser = new JSONParser();
        JSONObject obj = null;
        String c = "";
        if (cursor != null)
        {
            if (query.contains("?"))
            {
                c = String.format("&cursor=%s", UrlEscapers.urlFormParameterEscaper().escape(cursor));
            }
            else
            {
                c = String.format("?cursor=%s", UrlEscapers.urlFormParameterEscaper().escape(cursor));
            }
            
        }

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
                get.addHeader("x-apikey", VT_API_KEY);
                CloseableHttpResponse resp;
                try {
                    resp = client.execute(get);
                } catch (IOException ex) {
                    if (interaction != null) {
                        interaction.notify(PluginNotificationLevel.FATAL, "Failed to query the VirusTotal web service " + ex.getMessage());
                    }
                    ex.printStackTrace();
                    return Boolean.FALSE;
                }

                try {
                    if (resp.getStatusLine().getStatusCode() == 200) {
                        String answer = EntityUtils.toString(resp.getEntity());
                        try {
                            obj = (JSONObject)parser.parse(answer);
                            if (obj.containsKey("meta"))
                            {
                                JSONObject meta = (JSONObject)obj.get("meta");
                                if (meta.containsKey("cursor"))
                                {
                                    cursor = (String)meta.get("cursor");
                                    
                                    if (cursor != null && !cursor.isEmpty())
                                    {
                                        JSONObject o1 = (JSONObject)getQuery(query, interaction, cursor);
                                        JSONArray a1 = (JSONArray)obj.get("data");
                                        if (o1 != null && o1.containsKey("data"))
                                        {
                                            JSONArray a2 = (JSONArray)o1.get("data");
                                            a1.addAll(a2);
                                        }
                                        obj.put("data", a1);
                                    }
                                }
                            }

                        } catch (ParseException ex) {
                            if (interaction != null) {
                                interaction.notify(PluginNotificationLevel.FATAL, "Could not parse the VirusTotal web service response");
                            }
                            return Boolean.FALSE;
                        }
                    } 
                    else if (resp.getStatusLine().getStatusCode() == 204)
                    {
                        try {
                            Thread.sleep(2000);
                        } catch (InterruptedException ex) {
                            Exceptions.printStackTrace(ex);
                        }
                        return getQuery(query, interaction);
                    }
                    else if (resp.getStatusLine().getStatusCode() == 404)
                    {
                        JSONObject notFound = new JSONObject();
                        notFound.put("response_code", 0);

                        return notFound;
                    }
                    else if (resp.getStatusLine().getStatusCode() == 401)
                    {
                        interaction.notify(PluginNotificationLevel.FATAL, "Authentication error, please check your API key.");
                        return Boolean.FALSE;
                    }
                    else if (resp.getStatusLine().getStatusCode() == 429)
                    {
                        interaction.notify(PluginNotificationLevel.FATAL, "Too many requests or quota exceeded.");
                        return Boolean.FALSE;
                    }
                    else if (resp.getStatusLine().getStatusCode() == 403)
                    {
                        interaction.notify(PluginNotificationLevel.FATAL, "Unable to perform this action.");
                        return Boolean.FALSE;
                    }
                    else {
                        if (interaction != null) {
                            interaction.notify(PluginNotificationLevel.FATAL, "Could not access the VirusTotal web service error code " + resp.getStatusLine().getStatusCode());
                        }
                        return Boolean.FALSE;
                    }
                } catch (IOException ex) {
                    ex.printStackTrace();
                    if (interaction != null) {
                        interaction.notify(PluginNotificationLevel.FATAL, "Could not read from the VirusTotal web service.");
                    }
                    return Boolean.FALSE;
                } catch (org.apache.http.ParseException ex) {
                    Exceptions.printStackTrace(ex);
                    return null;
                }
                break;
            }

        } catch (URISyntaxException ex) {
            Exceptions.printStackTrace(ex);
        }
        return obj;
    }
    
    private Hash drawHash(String end, GraphRecordStore result, JSONObject hash, boolean showAVResults)
    {
        Hash ret = new Hash();
        JSONObject attributes = (JSONObject)hash.get("attributes");
        String sha1 = (String) attributes.get("sha1");
        String sha256 = (String) attributes.get("sha256");
        String md5 = (String) attributes.get("md5");
        ret.setMd5(md5);
        Long firstSeen = (Long)attributes.get("first_submission_date");
        Long lastSeen = (Long)attributes.get("last_submission_date");
        JSONArray names = (JSONArray) attributes.get("names");
        ArrayList<String> filenames = new ArrayList<>();
        if (names != null)
        {
            for (Object b : names)
            {
                if (b != null)
                {
                    filenames.add((String)b);
                }
            }
        }
        result.set(end + VisualConcept.VertexAttribute.IDENTIFIER, md5);
        result.set(end + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);

        if (sha1 != null) {
            result.set(end + CyberConcept.VertexAttribute.SHA1, sha1);
        }
        if (sha256 != null) {
            result.set(end + CyberConcept.VertexAttribute.SHA256, sha256);
        }
        result.set(end + CyberConcept.VertexAttribute.MD5, md5);
        
        String ssDeep = (String)attributes.get("ssdeep");
        String vHash = (String)attributes.get("vhash");
        ret.setSsdeep(ssDeep);
        ret.setVhash(vHash);
        if (ssDeep != null)
        {
            result.set(end + CyberConcept.VertexAttribute.SSDEEP, ssDeep);
        }
        if (vHash != null)
        {
            result.set(end + CyberConcept.VertexAttribute.VHASH, vHash);
        }
        if (attributes.containsKey("pe_info"))
        {
            JSONObject peInfo = (JSONObject)attributes.get("pe_info");
            if (peInfo.containsKey("imphash"))
            {
                ret.setImphash((String)peInfo.get("imphash"));
                result.set(end + CyberConcept.VertexAttribute.IMPHASH, (String)peInfo.get("imphash"));
            }
        }

        if (attributes.containsKey("magic"))
        {
            result.set(end + AnalyticConcept.VertexAttribute.COMMENT, (String)attributes.get("magic"));
        }
        
        result.set(end + TemporalConcept.VertexAttribute.FIRST_SEEN, TemporalFormatting.formatAsZonedDateTime(Instant.ofEpochSecond(firstSeen).atOffset(ZoneOffset.UTC)));   
        result.set(end + TemporalConcept.VertexAttribute.LAST_SEEN, TemporalFormatting.formatAsZonedDateTime(Instant.ofEpochSecond(lastSeen).atOffset(ZoneOffset.UTC)));
        result.set(end + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, true);
        result.set(end + CyberConcept.VertexAttribute.FILENAME, String.join("\n", filenames) );

        // last analysis results
        JSONObject lastAnalysisStats = (JSONObject)attributes.get("last_analysis_stats");
        result.set(end + VirusTotalConcept.VertexAttribute.FAILURE_COUNT, (Long)lastAnalysisStats.get("failure"));
        result.set(end + VirusTotalConcept.VertexAttribute.CONFIRMED_TIMEOUT_COUNT, (Long)lastAnalysisStats.get("confirmed-timeout"));
        result.set(end + VirusTotalConcept.VertexAttribute.HARMLESS_COUNT, (Long)lastAnalysisStats.get("harmless"));
        result.set(end + VirusTotalConcept.VertexAttribute.MALICIOUS_COUNT, (Long)lastAnalysisStats.get("malicious"));
        result.set(end + VirusTotalConcept.VertexAttribute.SUSPICIOUS_COUNT, (Long)lastAnalysisStats.get("suspicious"));
        result.set(end + VirusTotalConcept.VertexAttribute.TIMEOUT_COUNT, (Long)lastAnalysisStats.get("timeout"));
        result.set(end + VirusTotalConcept.VertexAttribute.TYPE_UNSUPPORTED_COUNT, (Long)lastAnalysisStats.get("type-unsupported"));
        result.set(end + VirusTotalConcept.VertexAttribute.UNDETECTED_COUNT, (Long)lastAnalysisStats.get("undetected"));

        if (showAVResults) {
            JSONObject results = (JSONObject)attributes.get("last_analysis_results");
            for (Object a : results.keySet())
            {                        
                JSONObject avResult = (JSONObject)results.get((String)a);
                result.add();
                result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
                result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);

                result.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, String.format("%s-%s", md5, (String)avResult.get("engine_name")));
                result.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, VirusTotalConcept.VertexType.AV_RESULT);
                result.set(GraphRecordStoreUtilities.DESTINATION + VirusTotalConcept.VertexAttribute.AV_ENGINE, (String)avResult.get("engine_name"));
                result.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.SOURCE, PLUGIN_NAME);
                result.set(GraphRecordStoreUtilities.DESTINATION + VirusTotalConcept.VertexAttribute.CATEGORY,  (String)avResult.get("category"));
                result.set(GraphRecordStoreUtilities.DESTINATION + VirusTotalConcept.VertexAttribute.METHOD,  (String)avResult.get("method"));
                result.set(GraphRecordStoreUtilities.DESTINATION + CyberConcept.VertexAttribute.RESULT, (String) avResult.get("result"));
                result.set(GraphRecordStoreUtilities.DESTINATION + VirusTotalConcept.VertexAttribute.VERSION, (String) avResult.get("engine_version"));

                result.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.TransactionAttribute.COLOR, "Yellow");
                result.set(GraphRecordStoreUtilities.TRANSACTION + GraphRecordStoreUtilities.COMPLETE_WITH_SCHEMA_KEY, "false");
            }   
        }
        return ret;
    }

    private Hash queryHash(String hashValue, String hashType, GraphRecordStore result, boolean showAVResults, PluginInteraction interaction) {
        String url = String.format("%s/api/v3/intelligence/search?query=%s&limit=300", VT_URL, UrlEscapers.urlFormParameterEscaper().escape(hashValue));
        Object r = getQuery(url, interaction);
        int count = 0;
        Hash ret = null;

        while (r == null && !(r instanceof Boolean) && count < 2) {
            r = getQuery(url, interaction);
            count++;
        }
        if (r == null || r instanceof Boolean) {
            return null;
        }
        JSONObject res = (JSONObject) r;
     
        boolean added = false;
        JSONArray data = (JSONArray)res.get("data");
        for (Object o : data)
        {
            added = true;
            JSONObject element = (JSONObject)o;
            
            result.add();
            ret = drawHash(GraphRecordStoreUtilities.SOURCE, result, element, showAVResults);
            
            if (!ret.getMd5().equalsIgnoreCase(hashValue))
            {
                result.add();
                result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, hashValue);
                result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, hashType);
                result.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, hashValue);
                result.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, hashType);
                result.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, AnalyticConcept.TransactionType.SIMILARITY);
            }

            // now draw the domains
            url = String.format("%s/api/v3/files/%s/contacted_domains", VT_URL, UrlEscapers.urlFormParameterEscaper().escape(hashValue));
            Object d = getQuery(url, interaction);
            count = 0;

            while (r == null && !(r instanceof Boolean) && count < 2) {
                r = getQuery(url, interaction);
                count++;
            }
            if (r != null && !(r instanceof Boolean)) {
                JSONArray domains = (JSONArray)((JSONObject) d).get("data");
                for (Object d1 : domains)
                {
                    JSONObject domain = (JSONObject)d1;
                    result.add();
                    result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ret.getMd5());
                    result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);

                    drawDomain(GraphRecordStoreUtilities.DESTINATION, result, domain);
                }
            }
            // draw ips

            url = String.format("%s/api/v3/files/%s/contacted_ips", VT_URL, UrlEscapers.urlFormParameterEscaper().escape(hashValue));
            d = getQuery(url, interaction);
            count = 0;

            while (r == null && !(r instanceof Boolean) && count < 2) {
                r = getQuery(url, interaction);
                count++;
            }
            if (r != null && !(r instanceof Boolean)) {
                JSONArray ips = (JSONArray)((JSONObject) d).get("data");
                for (Object d1 : ips)
                {
                    JSONObject ip = (JSONObject)d1;

                    result.add();
                    result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ret.getMd5());
                    result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);

                    drawIP(GraphRecordStoreUtilities.DESTINATION, result, ip);
                }
            }
        } 
        if (!added) {
            result.add();
            result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, hashValue);
            result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, hashType);
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, false);

        }
        return ret;
    }
    
    private void drawIP(String end, GraphRecordStore result, JSONObject data)
    {
        String name = (String)data.get("id");
        JSONObject att = (JSONObject)data.get("attributes");
        String whois = (String)att.get("whois");
        
        result.set(end + VisualConcept.VertexAttribute.IDENTIFIER, name);
        String type = AnalyticConcept.VertexType.IP_ADDRESS.getName();
        if (name.contains("."))
        {
            type = AnalyticConcept.VertexType.IPV4.getName();
        }
        else if (name.contains(":"))
        {
            type = AnalyticConcept.VertexType.IPV6.getName();
        }
        result.set(end + AnalyticConcept.VertexAttribute.TYPE, type);
        result.set(end + "Whois", whois);
        if (att.containsKey("country"))
        {
            result.set(end + SpatialConcept.VertexAttribute.COUNTRY, (String)att.get("country"));
        }
    }
    
    private void drawDomain(String end, GraphRecordStore result, JSONObject data)
    {
        String name = (String)data.get("id");
        JSONObject att = (JSONObject)data.get("attributes");
        String whois = (String)att.get("whois");

        result.set(end + VisualConcept.VertexAttribute.IDENTIFIER, name);
        result.set(end + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);
        result.set(end + "Whois", whois);
    }
    
    private void pivotVHash(String md5, String vhash, boolean showAVResults, GraphRecordStore result, PluginInteraction interaction) {
        String url = String.format("%s/api/v3/intelligence/search?query=vhash:%s&limit=300", VT_URL, UrlEscapers.urlFormParameterEscaper().escape(String.format("\"%s\"",vhash) ) );
        Object r = getQuery(url, interaction);
        int count = 0;

        while (r == null && !(r instanceof Boolean) && count < 2) {
            r = getQuery(url, interaction);
            count++;
        }
        if (r == null || r instanceof Boolean) {
            return;
        }
        JSONArray data = (JSONArray)((JSONObject)r).get("data");
        if (data.isEmpty()) 
        {
            result.add();
            result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
            result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, false);
        }
        else
        {
            for (Object a : data)
            {
                JSONObject h = (JSONObject)a;
                result.add();
                result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
                result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, true);
                result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);

                drawHash(GraphRecordStoreUtilities.DESTINATION, result, h, showAVResults);
                result.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.TransactionAttribute.COLOR, "Blue");
                result.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, "vHash match");
                result.set(GraphRecordStoreUtilities.TRANSACTION + GraphRecordStoreUtilities.COMPLETE_WITH_SCHEMA_KEY, "false");   
            }
        }
    }
    
    private void pivotImpHash(String md5, String imphash, boolean showAVResults, GraphRecordStore result, PluginInteraction interaction) {
        String url = String.format("%s/api/v3/intelligence/search?query=imphash:%s&limit=300", VT_URL, UrlEscapers.urlFormParameterEscaper().escape(String.format("\"%s\"",imphash) ) );
        Object r = getQuery(url, interaction);
        int count = 0;

        while (r == null && !(r instanceof Boolean) && count < 2) {
            r = getQuery(url, interaction);
            count++;
        }
        if (r == null || r instanceof Boolean) {
            return;
        }
        JSONArray data = (JSONArray)((JSONObject)r).get("data");
        if (data.isEmpty()) 
        {
            result.add();
            result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
            result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, false);
        }
        else
        {
            for (Object a : data)
            {
                JSONObject h = (JSONObject)a;
                result.add();
                result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
                result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, true);
                result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);

                drawHash(GraphRecordStoreUtilities.DESTINATION, result, h, showAVResults);
                result.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.TransactionAttribute.COLOR, "Blue");
                result.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, "imphash match");
                result.set(GraphRecordStoreUtilities.TRANSACTION + GraphRecordStoreUtilities.COMPLETE_WITH_SCHEMA_KEY, "false");   
            }
        }
    }
    
    private void pivotSSDeep(String md5, String ssdeep, boolean showAVResults, GraphRecordStore result, PluginInteraction interaction) {
        String url = String.format("%s/api/v3/intelligence/search?query=ssdeep:%%22%s+40%%22&limit=300", VT_URL, UrlEscapers.urlFormParameterEscaper().escape(String.format("%s",ssdeep) ) );
        Object r = getQuery(url, interaction);
        int count = 0;

        while (r == null && !(r instanceof Boolean) && count < 2) {
            r = getQuery(url, interaction);
            count++;
        }
        if (r == null || r instanceof Boolean) {
            return;
        }
        JSONArray data = (JSONArray)((JSONObject)r).get("data");
        if (data.isEmpty()) 
        {
            result.add();
            result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
            result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, false);
        }
        else
        {
            for (Object a : data)
            {
                JSONObject h = (JSONObject)a;
                result.add();
                result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
                result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, true);
                result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);

                drawHash(GraphRecordStoreUtilities.DESTINATION, result, h, showAVResults);
                result.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.TransactionAttribute.COLOR, "Blue");
                result.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, "ssdeep match");
                result.set(GraphRecordStoreUtilities.TRANSACTION + GraphRecordStoreUtilities.COMPLETE_WITH_SCHEMA_KEY, "false");   
            }
        }
    }
    
    private void pivotSimilarTo(String md5, boolean showAVResults, GraphRecordStore result, PluginInteraction interaction) {
        String url = String.format("%s/api/v3/intelligence/search?query=similar-to:%s&limit=300", VT_URL, UrlEscapers.urlFormParameterEscaper().escape(md5) );
        Object r = getQuery(url, interaction);
        int count = 0;

        while (r == null && !(r instanceof Boolean) && count < 2) {
            r = getQuery(url, interaction);
            count++;
        }
        if (r == null || r instanceof Boolean) {
            return;
        }
        JSONArray data = (JSONArray)((JSONObject)r).get("data");
        if (data.isEmpty()) 
        {
            result.add();
            result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
            result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, false);
        }
        else
        {
            for (Object a : data)
            {
                JSONObject h = (JSONObject)a;
                result.add();
                result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
                result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, true);
                result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);

                drawHash(GraphRecordStoreUtilities.DESTINATION, result, h, showAVResults);
                result.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.TransactionAttribute.COLOR, "Blue");
                result.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, "Similar to match");
                result.set(GraphRecordStoreUtilities.TRANSACTION + GraphRecordStoreUtilities.COMPLETE_WITH_SCHEMA_KEY, "false");   
            }
        }
    }
    
    private void queryDomain(String domain, GraphRecordStore result, boolean showAVResults, PluginInteraction interaction) {
        String url = String.format("%s/api/v3/domains/%s", VT_URL, UrlEscapers.urlFormParameterEscaper().escape(domain));
        Object r = getQuery(url, interaction);
        int count = 0;

        while (r == null && !(r instanceof Boolean) && count < 2) {
            r = getQuery(url, interaction);
            count++;
        }
        if (r == null || r instanceof Boolean) {
            return;
        }
        JSONObject data = (JSONObject)((JSONObject)r).get("data");
        
        if (data==null) 
        {
            result.add();
            result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, domain);
            result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, false);
        }
        else
        {
            result.add();
            result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, domain);
            result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, true);
            
            JSONObject attributes = (JSONObject)data.get("attributes");
            Long firstSeen = (Long)attributes.get("creation_date");
            Long lastSeen = (Long)attributes.get("last_update_date");
            if (firstSeen != null)
            {
                result.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.FIRST_SEEN, TemporalFormatting.formatAsZonedDateTime(Instant.ofEpochSecond(firstSeen).atOffset(ZoneOffset.UTC)));   
            }
            if (lastSeen != null)
            {
                result.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.LAST_SEEN, TemporalFormatting.formatAsZonedDateTime(Instant.ofEpochSecond(lastSeen).atOffset(ZoneOffset.UTC)));
            }
            
            // draw categories
            JSONObject categories = (JSONObject)attributes.get("categories");
            ArrayList<String> c = new ArrayList<>();
            
            for (Object k : categories.keySet())
            {
                String key = (String)k;
                String value = (String)categories.get(key);
                c.add(String.format("%s : %s", key, value));
            }
            result.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.CATEGORY, String.join("\n", c));

            // last analysis results
            JSONObject lastAnalysisStats = (JSONObject)attributes.get("last_analysis_stats");
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.FAILURE_COUNT, (Long)lastAnalysisStats.get("failure"));
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.CONFIRMED_TIMEOUT_COUNT, (Long)lastAnalysisStats.get("confirmed-timeout"));
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HARMLESS_COUNT, (Long)lastAnalysisStats.get("harmless"));
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.MALICIOUS_COUNT, (Long)lastAnalysisStats.get("malicious"));
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.SUSPICIOUS_COUNT, (Long)lastAnalysisStats.get("suspicious"));
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.TIMEOUT_COUNT, (Long)lastAnalysisStats.get("timeout"));
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.TYPE_UNSUPPORTED_COUNT, (Long)lastAnalysisStats.get("type-unsupported"));
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.UNDETECTED_COUNT, (Long)lastAnalysisStats.get("undetected"));
        
            // now draw the relationships
            url = String.format("%s/api/v3/domains/%s/communicating_files?limit=40", VT_URL, UrlEscapers.urlFormParameterEscaper().escape(domain));
            r = getQuery(url, interaction);
            count = 0;

            while (r == null && !(r instanceof Boolean) && count < 2) {
                r = getQuery(url, interaction);
                count++;
            }
            if (r == null || r instanceof Boolean) {
                return;
            }
            JSONArray data1 = (JSONArray)((JSONObject)r).get("data");

            if (!data1.isEmpty()) 
            {

                for (Object a : data1)
                {
                    JSONObject hash = (JSONObject)a;

                    result.add();
                    result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, domain);
                    result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);
                    result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, true);

                    drawHash(GraphRecordStoreUtilities.DESTINATION, result, hash, showAVResults);
                    result.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.TransactionAttribute.COLOR, "Blue");
                    result.set(GraphRecordStoreUtilities.TRANSACTION + GraphRecordStoreUtilities.COMPLETE_WITH_SCHEMA_KEY, "false");   
                }
            }
        }
    }
    
    private void queryIP(String ip, String type, GraphRecordStore result, boolean showAVResults, PluginInteraction interaction) {
        String url = String.format("%s/api/v3/ip_addresses/%s/communicating_files", VT_URL, UrlEscapers.urlFormParameterEscaper().escape(ip));
        Object r = getQuery(url, interaction);
        int count = 0;

        while (r == null && !(r instanceof Boolean) && count < 2) {
            r = getQuery(url, interaction);
            count++;
        }
        if (r == null || r instanceof Boolean) {
            return;
        }
        
        JSONArray data = (JSONArray)((JSONObject)r).get("data");
        
        if (data.isEmpty()) 
        {
            result.add();
            result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
            result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, false);
        }
        else
        {
            for (Object a : data)
            {
                JSONObject hash = (JSONObject)a;

                result.add();
                result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
                result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, true);
                result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                drawHash(GraphRecordStoreUtilities.DESTINATION, result, hash, showAVResults);
                result.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.TransactionAttribute.COLOR, "Blue");
                result.set(GraphRecordStoreUtilities.TRANSACTION + GraphRecordStoreUtilities.COMPLETE_WITH_SCHEMA_KEY, "false");   
            }
        }
    }

    @Override
    protected RecordStore query(final RecordStore query, final PluginInteraction interaction, final PluginParameters parameters) throws PluginException {
        final GraphRecordStore result = new GraphRecordStore();
        final Map<String, PluginParameter<?>> params = parameters.getParameters();

        if (query.size() <= 0) {
            return result;
        }
        Preferences prefs = NbPreferences.forModule(ACSCPreferenceKeys.class);

        VT_URL = prefs.get(ACSCPreferenceKeys.VIRUS_TOTAL_URL, "");
        VT_API_KEY = prefs.get(ACSCPreferenceKeys.VIRUS_TOTAL_API_KEY, "");

        if (VT_URL == null || VT_URL.isEmpty()) {
            VT_URL = "https://virustotal.com";
        }
        if (VT_URL.endsWith("/"))
        {
            VT_URL = VT_URL.substring(0, VT_URL.length()-1);
        }

        boolean showAVResults = params.get(SHOW_AV_RESULTS_PARAMETER).getBooleanValue();
        final MultiChoiceParameterType.MultiChoiceParameterValue hashPivots = parameters.getMultiChoiceValue(HASH_PIVOTS_PARAMETER_ID);

        List<String> pivots = hashPivots.getChoices();
        
        query.reset();

        int i = 0;
        while (query.next()) {
            try {
                int id = Integer.parseInt(query.get(GraphRecordStoreUtilities.SOURCE + GraphRecordStoreUtilities.ID));
                String label = query.get(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.LABEL);
                String type = label.substring(label.lastIndexOf('<') + 1, label.lastIndexOf('>'));
                String searchValue = query.get(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER);
                
                interaction.setProgress(i, query.size(), "Querying on " + searchValue, true);

                if (type.equalsIgnoreCase(AnalyticConcept.VertexType.HASH.toString())
                        || type.equalsIgnoreCase(AnalyticConcept.VertexType.MD5.getName())
                        || type.equalsIgnoreCase(AnalyticConcept.VertexType.SHA1.getName())
                        || type.equalsIgnoreCase(AnalyticConcept.VertexType.SHA256.getName())) {
                    Hash hash = queryHash(searchValue, type, result, showAVResults, interaction);
                    
                    if (hash != null && pivots.size() > 0)
                    {
                        
                        if (pivots.contains("ssdeep") && hash.getSsdeep() != null)
                        {
                            pivotSSDeep(hash.getMd5(), hash.getSsdeep(), showAVResults, result, interaction);
                        }
                        if (pivots.contains("vHash") && hash.getVhash() != null)
                        {
                            pivotVHash(hash.getMd5(), hash.getVhash(), showAVResults, result, interaction);
                        }
                        if (pivots.contains("imphash") && hash.getImphash() != null)
                        {
                            pivotImpHash(hash.getMd5(), hash.getImphash(), showAVResults, result, interaction);
                        }
                        if (pivots.contains("Similar to") && hash.getImphash() != null)
                        {
                            pivotSimilarTo(hash.getMd5(), showAVResults, result, interaction);
                        }
                    }
                }
                else if (type.equalsIgnoreCase(AnalyticConcept.VertexType.HOST_NAME.getName())) {
                    queryDomain(searchValue, result, showAVResults, interaction);
                }
                else if (type.equalsIgnoreCase(AnalyticConcept.VertexType.IPV4.getName()) ||
                        type.equalsIgnoreCase(AnalyticConcept.VertexType.IPV6.getName()) ||
                        type.equalsIgnoreCase(AnalyticConcept.VertexType.IP_ADDRESS.getName())) {
                    queryIP(searchValue, type, result, showAVResults, interaction);
                }
                
                
            } catch (InterruptedException ex) {
                Exceptions.printStackTrace(ex);
            }
        }
        return result;
    }
}
