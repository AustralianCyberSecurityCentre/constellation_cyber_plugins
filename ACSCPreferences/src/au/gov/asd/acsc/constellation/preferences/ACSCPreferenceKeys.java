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

public final class ACSCPreferenceKeys {

    /**
     * Maxmind
     */
    public static final String MAXMIND_USERID = "maxmindUserId";
    public static final String MAXMIND_LICENCEKEY = "maxmindLicenceKey";

    public static final String MAXMIND_CITY_DIR = "maxmindCityDirectory";
    public static final String MAXMIND_ANONYMOUS_DIR = "maxmindAnonDirectory";
    public static final String MAXMIND_ISP_DIR = "maxmindISPDirectory";
    public static final String MAXMIND_DOMAIN_DIR = "maxmindDomainDirectory";
    public static final String MAXMIND_CONNECTION_TYPE_DIR = "maxmindConnectionTypeDirectory";

    public static final String VIRUS_TOTAL_URL = "virusTotalUrl";
    public static final String VIRUS_TOTAL_API_KEY = "virusTotalAPIKey";
    
    public static final String GREYNOISE_API_KEY = "greyNoiseAPIKey";
    
    public static final String INTEZER_API_KEY = "intezerAPIKey";
    
    public static final String SHODAN_API_KEY = "shodanAPIKey";

    private ACSCPreferenceKeys() {
    }
}
