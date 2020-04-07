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
package au.gov.asd.acsc.constellation.preferences;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.prefs.Preferences;
import javax.swing.JComponent;
import org.netbeans.spi.options.OptionsPanelController;
import org.openide.util.HelpCtx;
import org.openide.util.Lookup;
import org.openide.util.NbPreferences;

@OptionsPanelController.SubRegistration(
        location = "constellation",
        displayName = "#ACSCOptions_DisplayName",
        keywords = "#ACSCOptions_Keywords",
        keywordsCategory = "constellation/Preferences",
        position = 1000)
@org.openide.util.NbBundle.Messages({
    "ACSCOptions_DisplayName=ACSC",
    "ACSCOptions_Keywords=acsc"
})
public final class ACSCOptionsPanelController extends OptionsPanelController {

    private ACSCOptionsPanel panel;
    private final PropertyChangeSupport pcs = new PropertyChangeSupport(this);

    @Override
    public void update() {
        final Preferences prefs = NbPreferences.forModule(ACSCPreferenceKeys.class);
        final ACSCOptionsPanel acscOptionsPanel = getPanel();

        acscOptionsPanel.setMaxmindUserId(prefs.get(ACSCPreferenceKeys.MAXMIND_USERID, ""));
        acscOptionsPanel.setMaxmindAPIKey(prefs.get(ACSCPreferenceKeys.MAXMIND_LICENCEKEY, ""));
        acscOptionsPanel.setMaxmindCityDB(prefs.get(ACSCPreferenceKeys.MAXMIND_CITY_DIR, ""));
        acscOptionsPanel.setMaxmindAnonDB(prefs.get(ACSCPreferenceKeys.MAXMIND_ANONYMOUS_DIR, ""));
        acscOptionsPanel.setMaxmindISPDB(prefs.get(ACSCPreferenceKeys.MAXMIND_ISP_DIR, ""));
        acscOptionsPanel.setMaxmindDomainDB(prefs.get(ACSCPreferenceKeys.MAXMIND_DOMAIN_DIR, ""));
        acscOptionsPanel.setMaxmindConnectionTypeDB(prefs.get(ACSCPreferenceKeys.MAXMIND_CONNECTION_TYPE_DIR, ""));
        acscOptionsPanel.setVirusTotalUrl(prefs.get(ACSCPreferenceKeys.VIRUS_TOTAL_URL, "https://virustotal.com"));
        acscOptionsPanel.setVirusTotalAPIKey(prefs.get(ACSCPreferenceKeys.VIRUS_TOTAL_API_KEY, ""));
        acscOptionsPanel.setGreyNoiseAPIKey(prefs.get(ACSCPreferenceKeys.GREYNOISE_API_KEY, ""));
        acscOptionsPanel.setIntezerAPIKey(prefs.get(ACSCPreferenceKeys.INTEZER_API_KEY, ""));
        acscOptionsPanel.setShodanAPIKey(prefs.get(ACSCPreferenceKeys.SHODAN_API_KEY, ""));
    }

    @Override
    public void applyChanges() {
        if (isValid()) {
            pcs.firePropertyChange(OptionsPanelController.PROP_VALID, null, null);

            if (isChanged()) {
                pcs.firePropertyChange(OptionsPanelController.PROP_CHANGED, false, true);

                final Preferences prefs = NbPreferences.forModule(ACSCPreferenceKeys.class);
                final ACSCOptionsPanel acscOptionsPanel = getPanel();

                prefs.put(ACSCPreferenceKeys.MAXMIND_USERID, acscOptionsPanel.getMaxmindUserId());
                prefs.put(ACSCPreferenceKeys.MAXMIND_LICENCEKEY, acscOptionsPanel.getMaxmindAPIKey());
                prefs.put(ACSCPreferenceKeys.MAXMIND_CITY_DIR, acscOptionsPanel.getMaxmindCityDB());
                prefs.put(ACSCPreferenceKeys.MAXMIND_ANONYMOUS_DIR, acscOptionsPanel.getMaxmindAnonDB());
                prefs.put(ACSCPreferenceKeys.MAXMIND_ISP_DIR, acscOptionsPanel.getMaxmindISPDB());
                prefs.put(ACSCPreferenceKeys.MAXMIND_DOMAIN_DIR, acscOptionsPanel.getMaxmindDomainDB());
                prefs.put(ACSCPreferenceKeys.MAXMIND_CONNECTION_TYPE_DIR, acscOptionsPanel.getMaxmindConnectionTypeDB());
                prefs.put(ACSCPreferenceKeys.VIRUS_TOTAL_URL, acscOptionsPanel.getVirusTotalUrl());
                prefs.put(ACSCPreferenceKeys.VIRUS_TOTAL_API_KEY, acscOptionsPanel.getVirusTotalAPIKey());
                prefs.put(ACSCPreferenceKeys.GREYNOISE_API_KEY, acscOptionsPanel.getGreyNoiseAPIKey());
                prefs.put(ACSCPreferenceKeys.INTEZER_API_KEY, acscOptionsPanel.getIntezerAPIKey());
                prefs.put(ACSCPreferenceKeys.SHODAN_API_KEY, acscOptionsPanel.getShodanAPIKey());
            }
        }
    }

    @Override
    public void cancel() {
    }

    @Override
    public boolean isValid() {
        return true;
    }

    @Override
    public boolean isChanged() {
        final Preferences prefs = NbPreferences.forModule(ACSCPreferenceKeys.class);
        final ACSCOptionsPanel acscOptionsPanel = getPanel();
        final boolean changed
                = !((acscOptionsPanel.getMaxmindAPIKey() == null ? prefs.get(ACSCPreferenceKeys.MAXMIND_LICENCEKEY, "") == null : acscOptionsPanel.getMaxmindAPIKey().equals(prefs.get(ACSCPreferenceKeys.MAXMIND_LICENCEKEY, "")))
                && (acscOptionsPanel.getMaxmindUserId() == null ? prefs.get(ACSCPreferenceKeys.MAXMIND_USERID, "") == null : acscOptionsPanel.getMaxmindUserId().equals(prefs.get(ACSCPreferenceKeys.MAXMIND_USERID, "")))
                && (acscOptionsPanel.getMaxmindCityDB() == null ? prefs.get(ACSCPreferenceKeys.MAXMIND_CITY_DIR, "") == null : acscOptionsPanel.getMaxmindCityDB().equals(prefs.get(ACSCPreferenceKeys.MAXMIND_CITY_DIR, "")))
                && (acscOptionsPanel.getMaxmindAnonDB() == null ? prefs.get(ACSCPreferenceKeys.MAXMIND_ANONYMOUS_DIR, "") == null : acscOptionsPanel.getMaxmindAnonDB().equals(prefs.get(ACSCPreferenceKeys.MAXMIND_ANONYMOUS_DIR, "")))
                && (acscOptionsPanel.getMaxmindISPDB() == null ? prefs.get(ACSCPreferenceKeys.MAXMIND_ISP_DIR, "") == null : acscOptionsPanel.getMaxmindISPDB().equals(prefs.get(ACSCPreferenceKeys.MAXMIND_ISP_DIR, "")))
                && (acscOptionsPanel.getMaxmindDomainDB() == null ? prefs.get(ACSCPreferenceKeys.MAXMIND_DOMAIN_DIR, "") == null : acscOptionsPanel.getMaxmindDomainDB().equals(prefs.get(ACSCPreferenceKeys.MAXMIND_DOMAIN_DIR, "")))
                && (acscOptionsPanel.getVirusTotalUrl() == null ? prefs.get(ACSCPreferenceKeys.VIRUS_TOTAL_URL, "") == null : acscOptionsPanel.getVirusTotalUrl().equals(prefs.get(ACSCPreferenceKeys.VIRUS_TOTAL_URL, "")))
                && (acscOptionsPanel.getVirusTotalAPIKey() == null ? prefs.get(ACSCPreferenceKeys.VIRUS_TOTAL_API_KEY, "") == null : acscOptionsPanel.getVirusTotalAPIKey().equals(prefs.get(ACSCPreferenceKeys.VIRUS_TOTAL_API_KEY, "")))
                && (acscOptionsPanel.getGreyNoiseAPIKey() == null ? prefs.get(ACSCPreferenceKeys.GREYNOISE_API_KEY, "") == null : acscOptionsPanel.getGreyNoiseAPIKey().equals(prefs.get(ACSCPreferenceKeys.GREYNOISE_API_KEY, "")))
                && (acscOptionsPanel.getIntezerAPIKey() == null ? prefs.get(ACSCPreferenceKeys.INTEZER_API_KEY, "") == null : acscOptionsPanel.getIntezerAPIKey().equals(prefs.get(ACSCPreferenceKeys.INTEZER_API_KEY, "")))
                && (acscOptionsPanel.getShodanAPIKey() == null ? prefs.get(ACSCPreferenceKeys.SHODAN_API_KEY, "") == null : acscOptionsPanel.getShodanAPIKey().equals(prefs.get(ACSCPreferenceKeys.SHODAN_API_KEY, "")))
                && (acscOptionsPanel.getMaxmindConnectionTypeDB() == null ? prefs.get(ACSCPreferenceKeys.MAXMIND_CONNECTION_TYPE_DIR, "") == null : acscOptionsPanel.getMaxmindConnectionTypeDB().equals(prefs.get(ACSCPreferenceKeys.MAXMIND_CONNECTION_TYPE_DIR, ""))));

        return changed;
    }

    @Override
    public void addPropertyChangeListener(final PropertyChangeListener listener) {
        pcs.addPropertyChangeListener(listener);
    }

    @Override
    public void removePropertyChangeListener(final PropertyChangeListener listener) {
        pcs.removePropertyChangeListener(listener);
    }

    private ACSCOptionsPanel getPanel() {
        if (panel == null) {
            panel = new ACSCOptionsPanel(this);
        }
        return panel;
    }

    @Override
    public JComponent getComponent(final Lookup masterLookup) {
        return getPanel();
    }

    @Override
    public HelpCtx getHelpCtx() {
        return new HelpCtx("au.gov.asd.acsc.constellation.preferences.acsc");
        
    }
}
