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
package au.gov.asd.acsc.constellation.dataaccess.cyber.plugins.intezer;

import au.gov.asd.acsc.constellation.dataaccess.cyber.plugins.virustotal.VirusTotalConcept;
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
import au.gov.asd.tac.constellation.schema.analyticschema.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.ContentConcept;
import au.gov.asd.tac.constellation.security.proxy.ConstellationHttpProxySelector;
import au.gov.asd.tac.constellation.utilities.temporal.TemporalFormatting;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPlugin;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPluginCoreType;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.prefs.Preferences;
import org.apache.http.HttpHost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
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
@Messages("IntezerPlugin=Intezer Enrichment")
public class IntezerPlugin extends RecordStoreQueryPlugin implements DataAccessPlugin {
    
    private String token = null;
    private final String apiBase = "https://analyze.intezer.com/api/v2-0";

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
        return "Query Intezer";
    }

    @Override
    public PluginParameters createParameters() {
        final PluginParameters params = new PluginParameters();
        
        return params;
    }

    private JSONObject analyseByHash(String hash)
    {
        JSONObject result = null;
        String url = String.format("%s/analyze-by-hash", apiBase);
        JSONObject body = new JSONObject();
        body.put("hash", hash);
        
        ProxySelector ps = ConstellationHttpProxySelector.getDefault();
        try {
            List<Proxy> proxies = ps.select(new URI(apiBase));
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

                HttpPost post = new HttpPost(url);
                post.setEntity(new StringEntity(body.toJSONString()));
                post.setHeader("Accept", "application/json");
                post.setHeader("Content-type", "application/json");
                post.setHeader("Authorization", String.format("Bearer %s", token));

                CloseableHttpResponse resp;
                try {
                    resp = client.execute(post);
                    int statusCode = resp.getStatusLine().getStatusCode();
                    if (statusCode == 404)
                    {
                        // didn't find file.
                    }
                    else if (statusCode == 201) {
                        JSONParser parser = new JSONParser();
                        JSONObject o = (JSONObject)parser.parse(EntityUtils.toString(resp.getEntity()));
                        String resultUrl = (String)o.get("result_url");
                        
                        CloseableHttpResponse resp1 = null;
                        
                        while (resp1 == null || resp1.getStatusLine().getStatusCode() != 200)
                        {
                            Thread.sleep(5000);
                            HttpGet get = new HttpGet(String.format("%s%s", apiBase, resultUrl));
                            get.setHeader("Accept", "application/json");
                            get.setHeader("Authorization", String.format("Bearer %s", token));
                            if (resp1 != null)
                            {
                                resp1.close();
                            }
                            resp1 = client.execute(get);
                        }
                        
                        result = (JSONObject)parser.parse(EntityUtils.toString(resp1.getEntity())); 
                    }
                    else
                    {
                        System.out.println("Failed to create, Status code is " + statusCode);
                    }
                } catch (IOException ex) {
                    ex.printStackTrace();
                } catch (ParseException ex) {
                    Exceptions.printStackTrace(ex);
                } catch (InterruptedException ex) {
                    Exceptions.printStackTrace(ex);
                } 
            }
        } catch (URISyntaxException ex) {
            Exceptions.printStackTrace(ex);
        } catch (UnsupportedEncodingException ex) {
            Exceptions.printStackTrace(ex);
        }
        return result;
    }
    
    private JSONObject getSubAnalyses(String analysisId)
    {
        JSONObject result = null;
        String url = String.format("%s/analyses/%s/sub-analyses", apiBase, analysisId);
        
        ProxySelector ps = ConstellationHttpProxySelector.getDefault();
        try {
            List<Proxy> proxies = ps.select(new URI(apiBase));
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

                HttpGet get = new HttpGet(url);
                get.setHeader("Accept", "application/json");
                get.setHeader("Authorization", String.format("Bearer %s", token));

                CloseableHttpResponse resp;
                try {
                    resp = client.execute(get);
                    int statusCode = resp.getStatusLine().getStatusCode();
                    if (statusCode == 404)
                    {
                        // didn't find file.
                    }
                    else if (statusCode == 200) {
                        JSONParser parser = new JSONParser();
                        result = (JSONObject)parser.parse(EntityUtils.toString(resp.getEntity()));
                    }
                    else
                    {
                        System.out.println("Failed to get, Status code is " + statusCode);
                    }
                } catch (IOException ex) {
                    ex.printStackTrace();
                } catch (ParseException ex) {
                    Exceptions.printStackTrace(ex);
                }
            }
        } catch (URISyntaxException ex) {
            Exceptions.printStackTrace(ex);
        } 
        return result;
    }
    
    private JSONObject getSubAnalysisMetadata(String analysisId, String subAnalysisId)
    {
        JSONObject result = null;
        String url = String.format("%s/analyses/%s/sub-analyses/%s/metadata", apiBase, analysisId, subAnalysisId);
        
        ProxySelector ps = ConstellationHttpProxySelector.getDefault();
        try {
            List<Proxy> proxies = ps.select(new URI(apiBase));
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

                HttpGet get = new HttpGet(url);
                get.setHeader("Accept", "application/json");
                get.setHeader("Authorization", String.format("Bearer %s", token));

                CloseableHttpResponse resp;
                try {
                    resp = client.execute(get);
                    int statusCode = resp.getStatusLine().getStatusCode();
                    if (statusCode == 404)
                    {
                        // didn't find file.
                    }
                    else if (statusCode == 200) {
                        JSONParser parser = new JSONParser();
                        result = (JSONObject)parser.parse(EntityUtils.toString(resp.getEntity()));
                    }
                    else
                    {
                        System.out.println("Failed to get, Status code is " + statusCode);
                    }
                } catch (IOException ex) {
                    ex.printStackTrace();
                } catch (ParseException ex) {
                    Exceptions.printStackTrace(ex);
                }
            }
        } catch (URISyntaxException ex) {
            Exceptions.printStackTrace(ex);
        } 
     
        
        return result;
    }
    
    private JSONObject getSubAnalysisCodeReuse(String analysisId, String subAnalysisId)
    {
        JSONObject result = null;
        String url = String.format("%s/analyses/%s/sub-analyses/%s/code-reuse", apiBase, analysisId, subAnalysisId);
        
        ProxySelector ps = ConstellationHttpProxySelector.getDefault();
        try {
            List<Proxy> proxies = ps.select(new URI(apiBase));
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

                HttpGet get = new HttpGet(url);
                get.setHeader("Accept", "application/json");
                get.setHeader("Authorization", String.format("Bearer %s", token));

                CloseableHttpResponse resp;
                try {
                    resp = client.execute(get);
                    int statusCode = resp.getStatusLine().getStatusCode();
                    if (statusCode == 404)
                    {
                        // didn't find file.
                    }
                    else if (statusCode == 200) {
                        JSONParser parser = new JSONParser();
                        result = (JSONObject)parser.parse(EntityUtils.toString(resp.getEntity()));
                    }
                    else
                    {
                        System.out.println("Failed to get, Status code is " + statusCode);
                    }
                } catch (IOException ex) {
                    ex.printStackTrace();
                } catch (ParseException ex) {
                    Exceptions.printStackTrace(ex);
                }
            }
        } catch (URISyntaxException ex) {
            Exceptions.printStackTrace(ex);
        } 
        return result;
    }
    
    
    private void getToken(String apiKey)
    {
        String url = String.format("%s/get-access-token", apiBase);
        JSONObject body = new JSONObject();
        body.put("api_key", apiKey);
        ProxySelector ps = ConstellationHttpProxySelector.getDefault();
        try {
            List<Proxy> proxies = ps.select(new URI(apiBase));
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

                HttpPost post = new HttpPost(url);
                post.setEntity(new StringEntity(body.toJSONString()));
                post.setHeader("Accept", "application/json");
                post.setHeader("Content-type", "application/json");

                CloseableHttpResponse resp;
                try {
                    resp = client.execute(post);
                    if (resp.getStatusLine().getStatusCode() == 200) {
                        JSONParser parser = new JSONParser();
                        JSONObject o = (JSONObject)parser.parse(EntityUtils.toString(resp.getEntity()));
                        token = (String)o.get("result");
                    }
                } catch (IOException ex) {
                    ex.printStackTrace();
                } catch (ParseException ex) {
                    Exceptions.printStackTrace(ex);
                }
            }
        } catch (URISyntaxException ex) {
            Exceptions.printStackTrace(ex);
        } catch (UnsupportedEncodingException ex) {
            Exceptions.printStackTrace(ex);
        }
    }


    @Override
    protected RecordStore query(final RecordStore query, final PluginInteraction interaction, final PluginParameters parameters) throws PluginException {

        final RecordStore results = new GraphRecordStore();
        final Preferences prefs = NbPreferences.forModule(ACSCPreferenceKeys.class);
        final String apiKey = prefs.get(ACSCPreferenceKeys.INTEZER_API_KEY, null);
        

        if (apiKey == null || apiKey.isEmpty() ) {
            interaction.notify(PluginNotificationLevel.FATAL, "The API key has not been set.\nPlease update these at Setup > Options > CONSTELLATION > ACSC > Intezer");
            return results;
        }

        if (query.size() == 0) {
            return results;
        }

        query.reset();
        final Map<String, PluginParameter<?>> params = parameters.getParameters();
        
        if (token == null)
        {
            getToken(apiKey);
            if (token == null)
            {
                // failed to get the token
                return results;
            }
        }
        
        while (query.next()) {
            String identifier = query.get(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER);
            String type = query.get(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE);
            if (type.equals(AnalyticConcept.VertexType.HASH.toString())
                    || type.equals(AnalyticConcept.VertexType.MD5.toString())
                    || type.equals(AnalyticConcept.VertexType.SHA256.toString())          
                    || type.equals(AnalyticConcept.VertexType.SHA1.toString())) {
                
                
                
                JSONObject o = analyseByHash(identifier);
                
                // now get the sub analysis results
                JSONObject r = (JSONObject)o.get("result");
                String verdict = (String)r.get("verdict");
                String subVerdict = (String)r.get("sub_verdict");
                String analysisTime = (String)r.get("analysis_time");
                String familyName = (String)r.get("family_name");
                String analysisId = (String)r.get("analysis_id");
                String analysisUrl = (String)r.get("analysis_url");
                
                results.add();
                results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.VERDICT, verdict);
                results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.COMMENT, subVerdict);
                results.set(GraphRecordStoreUtilities.SOURCE + ContentConcept.VertexAttribute.URL, analysisUrl);
                results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.COMMENT, subVerdict);
                results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.ANALYSIS_TIME, TemporalFormatting.completeZonedDateTimeString(analysisTime));
                
                results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, familyName);
                results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.CODE_FAMILY);
                
                HashMap<Long, String> pidToDisplayName = new HashMap<>();
                HashMap<String, Long> md5ToPid = new HashMap<>();
                HashMap<Long, Long> pidToPPid = new HashMap<>();
                
                JSONObject sa = getSubAnalyses(analysisId);
                
                
                JSONArray subAnalyses = (JSONArray)sa.get("sub_analyses");
                for (Object a : subAnalyses)
                {
                    JSONObject subAnalysis = (JSONObject)a;
                    String source = (String)subAnalysis.get("source");
                    String subAnalysisId = (String)subAnalysis.get("sub_analysis_id");
                                        
                    JSONObject subAnalysisMetadata = getSubAnalysisMetadata(analysisId, subAnalysisId);
                    
                    String md5 = (String)subAnalysisMetadata.get("md5");
                    String sha1 = (String)subAnalysisMetadata.get("sha1");
                    String sha256 = (String)subAnalysisMetadata.get("sha256");
                                        
                    String ssdeep = (String)subAnalysisMetadata.get("ssdeep");
                    String architecture = (String)subAnalysisMetadata.get("architecture");
                    Long size = (Long)subAnalysisMetadata.get("size_in_bytes");
                    String fileType = (String)subAnalysisMetadata.get("file_type");
                    String company = (String)subAnalysisMetadata.get("company");
                    String product = (String)subAnalysisMetadata.get("product");
                    String productVersion = (String)subAnalysisMetadata.get("product_version");
                    String originalFilename = (String)subAnalysisMetadata.get("original_filename");
                    String compilationTimestamp = (String)subAnalysisMetadata.get("compilation_timestamp");
                    
                    results.add();
                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);
                    results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.SHA1, sha1);
                    results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.SHA256, sha256);
                    results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.SSDEEP, ssdeep);
                    results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.SIZE, size);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.SOURCE, source);
                    results.set(GraphRecordStoreUtilities.SOURCE + "Architecture", architecture);
                    results.set(GraphRecordStoreUtilities.SOURCE + "File Type", fileType);
                    results.set(GraphRecordStoreUtilities.SOURCE + "Company", company);
                    results.set(GraphRecordStoreUtilities.SOURCE + "Product", product);
                    results.set(GraphRecordStoreUtilities.SOURCE + "Product Version", productVersion);
                    results.set(GraphRecordStoreUtilities.SOURCE + "Original Filename", originalFilename);
                    results.set(GraphRecordStoreUtilities.SOURCE + "Compilation Timestamp", compilationTimestamp);
                    
                    

                    if (subAnalysis.containsKey("extraction_info"))
                    {
                        JSONObject extractionInfo = (JSONObject)subAnalysis.get("extraction_info");
                        String collectedFrom = (String)extractionInfo.get("collected_from");
                        JSONArray processes = (JSONArray)extractionInfo.get("processes");
                        for (Object p : processes)
                        {
                            JSONObject process = (JSONObject)p;
                            Long parentProcessId = (Long)process.get("parent_process_id");
                            Long processId = (Long)process.get("process_id");
                            md5ToPid.put(md5, processId);
                            pidToPPid.put(processId, parentProcessId);
                            String processPath = (String)process.get("process_path");
                            String modulePath = (String)process.get("module_path");
                            
                            String displayName = String.format("%s %s", processPath, processId);
                            
                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);
                            results.set(GraphRecordStoreUtilities.SOURCE + "Module Path", modulePath);
                            results.set(GraphRecordStoreUtilities.SOURCE + "Collect From", collectedFrom);
                            
                            pidToDisplayName.put(processId, displayName);
                        }   
                    } 
                    
                    JSONObject codeReuse = getSubAnalysisCodeReuse(analysisId, subAnalysisId);
                    if (codeReuse != null)
                    {
                        JSONArray families = (JSONArray)codeReuse.get("families");
                        for (Object f : families)
                        {
                            JSONObject family = (JSONObject)f;
                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);
                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, (String)family.get("family_name"));
                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.CODE_FAMILY);
                            results.set(GraphRecordStoreUtilities.DESTINATION + CyberConcept.VertexAttribute.FAMILY_TYPE, (String)family.get("family_type"));
                            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.COUNT, (Long)family.get("reused_gene_count"));
                        }
                    }
                    
                }
                for (String md5 : md5ToPid.keySet())
                {
                    Long pid = md5ToPid.get(md5);
                    String displayName = pidToDisplayName.get(pid);
                    results.add();
                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);

                    results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, displayName);
                    results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.PROCESS);
                }
                
                for (Long pid : pidToPPid.keySet())
                {
                    Long ppid = pidToPPid.get(pid);
                    String displayName = pidToDisplayName.get(ppid);
                    if (displayName != null)
                    {
                        results.add();
                        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, displayName);
                        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.PROCESS);

                        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, pidToDisplayName.get(pid));
                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.PROCESS);
                    }
                    else
                    {
                        results.add();
                        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, pidToDisplayName.get(pid));
                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.PROCESS);
                    }
                }
                
                
            }
        }
        
        
        return results;
    }

}
