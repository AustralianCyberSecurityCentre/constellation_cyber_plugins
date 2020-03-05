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
package au.gov.asd.acsc.constellation.dataaccess.cyber.plugins.maxmind;

import au.gov.asd.acsc.constellation.preferences.ACSCPreferenceKeys;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStore;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStoreUtilities;
import au.gov.asd.tac.constellation.graph.processing.RecordStore;
import au.gov.asd.tac.constellation.graph.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.pluginframework.Plugin;
import au.gov.asd.tac.constellation.pluginframework.PluginException;
import au.gov.asd.tac.constellation.pluginframework.PluginInteraction;
import au.gov.asd.tac.constellation.pluginframework.PluginNotificationLevel;
import au.gov.asd.tac.constellation.pluginframework.parameters.PluginParameters;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.SpatialConcept;
import au.gov.asd.tac.constellation.security.proxy.ConstellationHttpProxySelector;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPlugin;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPluginCoreType;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.WebServiceClient;
import com.maxmind.geoip2.exception.AuthenticationException;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.AnonymousIpResponse;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.model.ConnectionTypeResponse;
import com.maxmind.geoip2.model.DomainResponse;
import com.maxmind.geoip2.model.IspResponse;
import com.maxmind.geoip2.record.City;
import com.maxmind.geoip2.record.Country;
import com.maxmind.geoip2.record.Location;
import com.maxmind.geoip2.record.Postal;
import com.maxmind.geoip2.record.Subdivision;
import com.maxmind.geoip2.record.Traits;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.List;
import java.util.logging.Logger;
import java.util.prefs.Preferences;
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
@Messages("MaxmindPlugin=Maxmind IP Enrichment")
public class MaxmindPlugin extends RecordStoreQueryPlugin implements DataAccessPlugin {

    private static final Logger LOGGER = Logger.getLogger(MaxmindPlugin.class.getName());

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
        return "Query Maxmind API";
    }

    @Override
    public PluginParameters createParameters() {
        final PluginParameters params = new PluginParameters();
        return params;
    }

    private void queryDBs(final RecordStore query, final PluginInteraction interaction, RecordStore results, String city, String anon, String isp, String domain, String connectionType) {
        query.reset();

        DatabaseReader cityClient = null;
        DatabaseReader anonClient = null;
        DatabaseReader ispClient = null;
        DatabaseReader domainClient = null;
        DatabaseReader connectionTypeClient = null;
        try {
            File cityDB = new File(city);
            cityClient = new DatabaseReader.Builder(cityDB).build();
        } catch (IOException ex) {
            ex.printStackTrace();
            interaction.notify(PluginNotificationLevel.FATAL, "Unable to open the City DB file.");
            return;
        }
        if (anon != null && !anon.isEmpty()) {
            try {
                File db = new File(city);
                anonClient = new DatabaseReader.Builder(db).build();
            } catch (IOException ex) {
                interaction.notify(PluginNotificationLevel.FATAL, "Unable to open the Anonymous DB file.");
                return;
            }
        }
        if (isp != null && !isp.isEmpty()) {
            try {
                File db = new File(isp);
                ispClient = new DatabaseReader.Builder(db).build();
            } catch (IOException ex) {
                interaction.notify(PluginNotificationLevel.FATAL, "Unable to open the ISP DB file.");
                return;
            }
        }
        if (domain != null && !domain.isEmpty()) {
            try {

                File db = new File(domain);
                domainClient = new DatabaseReader.Builder(db).build();
            } catch (IOException ex) {
                interaction.notify(PluginNotificationLevel.FATAL, "Unable to open the Domain DB file.");
                return;
            }
        }
        if (connectionType != null && !connectionType.isEmpty()) {
            try {

                File db = new File(connectionType);
                connectionTypeClient = new DatabaseReader.Builder(db).build();
            } catch (IOException ex) {
                interaction.notify(PluginNotificationLevel.FATAL, "Unable to open the Connection Type DB file.");
                return;
            }
        }

        while (query.next()) {
            try {
                String identifier = query.get(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER);
                String type = query.get(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE);

                if (type.equals(AnalyticConcept.VertexType.IPV4.toString())
                        || type.equals(AnalyticConcept.VertexType.IPV6.toString())
                        || type.equals(AnalyticConcept.VertexType.IP_ADDRESS.toString())) {
                    InetAddress ipAddress = null;
                    try {
                        ipAddress = InetAddress.getByName(identifier);
                    } catch (UnknownHostException ex) {
                        // is invalid ip address, just skip.
                    }
                    if (ipAddress != null) {
                        CityResponse cityResponse = cityClient.city(ipAddress);
                        drawCityResponse(identifier, type, cityResponse, results);

                        if (anonClient != null) {
                            AnonymousIpResponse anonResponse = anonClient.anonymousIp(ipAddress);
                            results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.IS_ANONYMOUS, anonResponse.isAnonymous());
                            results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.IS_ANONYMOUS_VPN, anonResponse.isAnonymousVpn());
                            results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.IS_HOSTING_PROVIDER, anonResponse.isHostingProvider());
                            results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.IS_PUBLIC_PROXY, anonResponse.isPublicProxy());
                            results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.IS_TOR_EXIT_NODE, anonResponse.isTorExitNode());
                        }

                        if (ispClient != null) {
                            IspResponse ispResponse = ispClient.isp(ipAddress);
                            results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.ISP, ispResponse.getIsp());
                            results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.ORGANISATION, ispResponse.getOrganization());
                            results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.ASN_ORGANISATION, ispResponse.getAutonomousSystemOrganization());
                            results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.ASN, ispResponse.getAutonomousSystemNumber().toString());
                        }

                        if (domainClient != null) {
                            DomainResponse domainResponse = domainClient.domain(ipAddress);
                            results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.DOMAIN, domainResponse.getDomain());
                        }

                        if (connectionTypeClient != null) {
                            ConnectionTypeResponse connectionTypeResponse = connectionTypeClient.connectionType(ipAddress);
                            if (connectionTypeResponse.getConnectionType() != null)
                            {
                                results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.CONNECTION_TYPE, connectionTypeResponse.getConnectionType().toString());
                            }
                        }
                    }
                }
            } catch (IOException ex) {
                interaction.notify(PluginNotificationLevel.ERROR, String.format("Exception querying the Maxmind API: %s", ex.getMessage()));
                return;
            } catch (GeoIp2Exception ex) {
                interaction.notify(PluginNotificationLevel.ERROR, ex.getMessage());
                Exceptions.printStackTrace(ex);
                return;
            }
        }
    }

    private void drawCityResponse(String identifier, String type, CityResponse response, RecordStore results) {
        Country country = response.getCountry();
        results.add();

        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.COUNTRY, country.getName());

        Subdivision subdivision = response.getMostSpecificSubdivision();
        results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.SUBDIVISION, subdivision.getName());

        City city = response.getCity();
        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.CITY, city.getName());

        Postal postal = response.getPostal();
        results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.POSTAL, postal.getCode());

        Location location = response.getLocation();

        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.LATITUDE, location.getLatitude());
        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.LONGITUDE, location.getLongitude());
        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.ACCURACY, location.getAccuracyRadius());
    }

    private void queryAPI(final RecordStore query, final PluginInteraction interaction, RecordStore results, String userId, String apiKey) {
        query.reset();

        ProxySelector ps = ConstellationHttpProxySelector.getDefault();
        try {
            List<Proxy> proxies = ps.select(new URI("https://geoip.maxmind.com"));
            for (Proxy proxy : proxies) {
                try (WebServiceClient client = new WebServiceClient.Builder(Integer.parseInt(userId), apiKey).proxy(proxy).build()) {
                    while (query.next()) {
                        String identifier = query.get(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER);
                        String type = query.get(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE);
                        if (type.equals(AnalyticConcept.VertexType.IPV4.toString())
                                || type.equals(AnalyticConcept.VertexType.IPV6.toString())
                                || type.equals(AnalyticConcept.VertexType.IP_ADDRESS.toString())) {

                            try {
                                InetAddress ipAddress = InetAddress.getByName(identifier);

                                CityResponse response = client.city(ipAddress);
                                drawCityResponse(identifier, type, response, results);

                                Traits traits = response.getTraits();
                                if (traits != null) {
                                    if (traits.getConnectionType() != null) {
                                        results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.CONNECTION_TYPE, traits.getConnectionType().toString());
                                    }
                                    results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.IS_ANONYMOUS, traits.isAnonymous());
                                    results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.IS_ANONYMOUS_PROXY, traits.isAnonymousProxy());
                                    results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.IS_ANONYMOUS_VPN, traits.isAnonymousVpn());
                                    results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.IS_HOSTING_PROVIDER, traits.isHostingProvider());
                                    results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.IS_LEGITIMATE_PROXY, traits.isLegitimateProxy());
                                    results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.IS_PUBLIC_PROXY, traits.isPublicProxy());
                                    results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.IS_TOR_EXIT_NODE, traits.isTorExitNode());

                                    results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.DOMAIN, traits.getDomain());
                                    results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.ISP, traits.getIsp());
                                    results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.ORGANISATION, traits.getOrganization());
                                    results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.ASN_ORGANISATION, traits.getAutonomousSystemOrganization());
                                    results.set(GraphRecordStoreUtilities.SOURCE + MaxmindConcept.VertexAttribute.ASN, traits.getAutonomousSystemNumber().toString());
                                }
                            } catch (AuthenticationException ex) {
                                interaction.notify(PluginNotificationLevel.ERROR, "Failed to authenticate to the Maxmind API, please check your credentials.");
                                return;
                            } catch (UnknownHostException ex) {
                                interaction.notify(PluginNotificationLevel.ERROR, "Unable to contact the Maxmind API, please check your network connectivity and proxy settings.");
                                return;
                            } catch (IOException ex) {
                                interaction.notify(PluginNotificationLevel.ERROR, String.format("Exception querying the Maxmind API: %s", ex.getMessage()));
                                return;
                            } catch (GeoIp2Exception ex) {
                                interaction.notify(PluginNotificationLevel.ERROR, ex.getMessage());
                                Exceptions.printStackTrace(ex);
                                return;
                            }
                        }
                    }
                } catch (IOException ex) {
                    interaction.notify(PluginNotificationLevel.ERROR, "Unable to create the client to interact with the Maxmind API.\nPlease try again later, if you continue to see this error, contact your administrator.");
                    Exceptions.printStackTrace(ex);
                    return;
                }
                break;
            }
        } catch (URISyntaxException ex) {
            // should never occur as the maxmind URI is solid.
            Exceptions.printStackTrace(ex);
        }
    }

    @Override
    protected RecordStore query(final RecordStore query, final PluginInteraction interaction, final PluginParameters parameters) throws PluginException {

        final RecordStore results = new GraphRecordStore();
        final Preferences prefs = NbPreferences.forModule(ACSCPreferenceKeys.class);
        final String apiKey = prefs.get(ACSCPreferenceKeys.MAXMIND_LICENCEKEY, null);
        final String userId = prefs.get(ACSCPreferenceKeys.MAXMIND_USERID, null);
        final String cityDir = prefs.get(ACSCPreferenceKeys.MAXMIND_CITY_DIR, null);
        final String anonDir = prefs.get(ACSCPreferenceKeys.MAXMIND_ANONYMOUS_DIR, null);
        final String ispDir = prefs.get(ACSCPreferenceKeys.MAXMIND_ISP_DIR, null);
        final String domainDir = prefs.get(ACSCPreferenceKeys.MAXMIND_DOMAIN_DIR, null);
        final String connectionTypeDir = prefs.get(ACSCPreferenceKeys.MAXMIND_CONNECTION_TYPE_DIR, null);

        if ((apiKey == null || apiKey.isEmpty() || userId == null || userId.isEmpty()) && (cityDir == null || cityDir.isEmpty())) {
            interaction.notify(PluginNotificationLevel.FATAL, "The User Id and API key/DB locations have not been set.\nPlease update these at Setup > Options > CONSTELLATION > ACSC");
            return results;
        }

        if (query.size() == 0) {
            return results;
        }
        if (cityDir != null && !cityDir.isEmpty()) {
            queryDBs(query, interaction, results, cityDir, anonDir, ispDir, domainDir, connectionTypeDir);
        } else {
            queryAPI(query, interaction, results, userId, apiKey);
        }

        return results;
    }

}
