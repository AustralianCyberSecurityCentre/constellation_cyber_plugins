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
import au.gov.asd.tac.constellation.graph.schema.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.plugins.Plugin;
import au.gov.asd.tac.constellation.plugins.PluginException;
import au.gov.asd.tac.constellation.plugins.PluginInteraction;
import au.gov.asd.tac.constellation.plugins.PluginNotificationLevel;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameter;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameters;
import au.gov.asd.tac.constellation.plugins.parameters.types.BooleanParameterType;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.TemporalConcept;
import au.gov.asd.tac.constellation.security.proxy.ConstellationHttpProxySelector;
import au.gov.asd.tac.constellation.utilities.temporal.TemporalFormatting;
import au.gov.asd.tac.constellation.views.dataaccess.plugins.DataAccessPlugin;
import au.gov.asd.tac.constellation.views.dataaccess.plugins.DataAccessPluginCoreType;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import com.google.common.net.UrlEscapers;
import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
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

    private static final Logger LOGGER = Logger.getLogger(VirusTotalPlugin.class.getName());
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
    public static final String FLAG_POSITIVES_ONLY_PARAMETER = PluginParameter.buildId(VirusTotalPlugin.class, "flagPositivesOnly");

    @Override
    public PluginParameters createParameters() {
        final PluginParameters params = new PluginParameters();

        final PluginParameter<BooleanParameterType.BooleanParameterValue> showAVResults = BooleanParameterType.build(SHOW_AV_RESULTS_PARAMETER);
        showAVResults.setName("Show AntiVirus Results");
        showAVResults.setDescription("Show AntiVirus Results");
        showAVResults.setBooleanValue(true);
        params.addParameter(showAVResults);

        final PluginParameter<BooleanParameterType.BooleanParameterValue> flagPositivesOnly = BooleanParameterType.build(FLAG_POSITIVES_ONLY_PARAMETER);
        flagPositivesOnly.setName("Flag Positives only");
        flagPositivesOnly.setDescription("Flag Positives only");
        flagPositivesOnly.setBooleanValue(true);
        params.addParameter(flagPositivesOnly);

        return params;
    }

    private Object getQuery(String query, PluginInteraction interaction) {

        JSONParser parser = new JSONParser();
        Object obj = null;
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

                HttpGet get = new HttpGet(query);
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
                            obj = parser.parse(answer);
                        } catch (ParseException ex) {
                            if (interaction != null) {
                                interaction.notify(PluginNotificationLevel.FATAL, "Could not parse the VirusTotal web service response");
                            }
                            return null;
                        }
                    } 
                    else if (resp.getStatusLine().getStatusCode() == 403)
                    {
                        interaction.notify(PluginNotificationLevel.FATAL, "Could authenticate to the VirusTotal service");
                        return Boolean.FALSE;
                    }
                    else {
                        if (interaction != null) {
                            interaction.notify(PluginNotificationLevel.FATAL, "Could not access the VirusTotal web service error code " + resp.getStatusLine().getStatusCode());
                        }
                        return null;
                    }
                } catch (IOException ex) {
                    if (interaction != null) {
                        interaction.notify(PluginNotificationLevel.FATAL, "Could not read from the VirusTotal web service.");
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
        return obj;
    }


    private void drawHash(GraphRecordStore result, String hashValue, String hashType, String md5, String sha256, String sha1, String filename) {
        if (md5 == null || md5.trim().isEmpty()) {
            return;
        }

        result.add();
        result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, hashValue);
        result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, hashType);

        if (sha1 != null) {
            result.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.SHA1, sha1);
        }
        if (sha256 != null) {
            result.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.SHA256, sha256);
        }
        result.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.MD5, md5);
        
        if (filename != null) {
            result.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.FILENAME, filename);
        }

    }

    private void queryHash(String hashValue, String hashType, GraphRecordStore result, boolean showAVResults, boolean flagPositivesOnly, PluginInteraction interaction) {
        String VT_BASE_URL = VT_URL + "/vtapi/v2/file/report?resource=";
        String url = String.format("%s%s&apikey=%s", VT_BASE_URL, UrlEscapers.urlFormParameterEscaper().escape(hashValue), VT_API_KEY);
        Object r = getQuery(url, interaction);
        int count = 0;

        while (r == null && !(r instanceof Boolean) && count < 10) {
            r = getQuery(url, interaction);
            count++;
        }
        if (r == null || r instanceof Boolean) {
            return;
        }
        JSONObject res = (JSONObject) r;
        result.add();
        result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, hashValue);
        result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, hashType);

        if (res.containsKey("response_code") && ((Long) res.get("response_code")).intValue() == 1) {

            String sha1 = (String) res.get("sha1");
            String sha256 = (String) res.get("sha256");
            String md5 = (String) res.get("md5");
            int hits = ((Long) res.get("positives")).intValue();

            String firstSeen = (String) res.get("first_seen");
            String lastSeen = (String) res.get("last_seen");

            JSONArray names = (JSONArray) res.get("names");

            String filenames = "";
            if (names != null) {
                for (Object o : names) {
                    filenames += o.toString() + ", ";
                }
            }

            if (!filenames.isEmpty()) {
                filenames = filenames.substring(0, filenames.length() - 2);
            }

            result.add();
            result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, hashValue);
            result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, hashType);
            result.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.FIRST_SEEN, TemporalFormatting.completeZonedDateTimeString(firstSeen));
            result.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.LAST_SEEN, TemporalFormatting.completeZonedDateTimeString(lastSeen));
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, true);

            if ((!flagPositivesOnly) || (flagPositivesOnly && hits > 0)) {

                result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, hashValue);
                result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.AV_HITS, hits);

                JSONObject scans = (JSONObject) res.get("scans");
                String avResults = "";

                for (Object key : scans.keySet()) {
                    JSONObject scan = (JSONObject) scans.get(key);
                    if ((boolean) scan.get("detected")) {
                        avResults += key.toString() + ":" + (String) scan.get("result") + "\n";
                    }
                }
                result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.COMMENT, avResults);
                if (avResults.isEmpty()) {
                    result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.DETECTED, false);
                } else {
                    result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.DETECTED, true);
                }

                drawHash(result, hashValue, hashType, md5, sha256, sha1, filenames);

                if (showAVResults) {
                    // add Relationships

                    for (Object key : scans.keySet()) {
                        JSONObject scan = (JSONObject) scans.get(key);
                        String nodeKey = key.toString() + ":" + (String) scan.get("result");
                        if ((boolean) scan.get("detected") || !flagPositivesOnly) {
                            result.add();
                            result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, hashValue);
                            result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, hashType);

                            result.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, nodeKey);
                            result.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, VirusTotalConcept.VertexType.AV_RESULT);
                            result.set(GraphRecordStoreUtilities.DESTINATION + VirusTotalConcept.VertexAttribute.AV_ENGINE, key.toString());
                            result.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.SOURCE, pluginName);
                            result.set(GraphRecordStoreUtilities.DESTINATION + VirusTotalConcept.VertexAttribute.DETECTED, (boolean) scan.get("detected"));
                            result.set(GraphRecordStoreUtilities.DESTINATION + VirusTotalConcept.VertexAttribute.RESULT, (String) scan.get("result"));
                            result.set(GraphRecordStoreUtilities.DESTINATION + VirusTotalConcept.VertexAttribute.VERSION, (String) scan.get("version"));

                            result.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.TransactionAttribute.COLOR, "Yellow");
                            result.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.TransactionAttribute.IDENTIFIER, nodeKey + ":" + hashValue);
                            result.set(GraphRecordStoreUtilities.TRANSACTION + GraphRecordStoreUtilities.COMPLETE_WITH_SCHEMA_KEY, "false");
                        }
                    }
                }
            }

        } else {
            result.set(GraphRecordStoreUtilities.SOURCE + VirusTotalConcept.VertexAttribute.HAS_VIRUS_TOTAL_ENTRY, false);

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

        boolean showAVResults = params.get(SHOW_AV_RESULTS_PARAMETER).getBooleanValue();
        boolean flagPositivesOnly = params.get(FLAG_POSITIVES_ONLY_PARAMETER).getBooleanValue();

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
                    queryHash(searchValue, type, result, showAVResults, flagPositivesOnly, interaction);
                }
            } catch (InterruptedException ex) {
                Exceptions.printStackTrace(ex);
            }
        }
        return result;
    }
}
