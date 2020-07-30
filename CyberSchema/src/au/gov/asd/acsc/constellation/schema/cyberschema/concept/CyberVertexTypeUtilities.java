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
package au.gov.asd.acsc.constellation.schema.cyberschema.concept;

import au.gov.asd.tac.constellation.graph.schema.type.SchemaVertexType;

import au.gov.asd.tac.constellation.utilities.color.ConstellationColor;
import au.gov.asd.tac.constellation.utilities.icon.CharacterIconProvider;
import au.gov.asd.tac.constellation.utilities.icon.DefaultIconProvider;
import java.util.HashMap;
import java.util.Map;

public class CyberVertexTypeUtilities {

    public static final String STRENGTH_PROPERTY = "Strength";
    public static final String REALM_PROPERTY = "Realm";

    private static final Map<String, Boolean> PROPERTY_INHERITANCE = new HashMap<>();

    static {
        PROPERTY_INHERITANCE.put(STRENGTH_PROPERTY, true);
        PROPERTY_INHERITANCE.put(REALM_PROPERTY, false);
    }

    private static final SchemaVertexType UNSUPPORTED = new SchemaVertexType.Builder("Unsupported")
            .setDescription("")
            .setColor(ConstellationColor.GOLDEN_ROD)
            .setForegroundIcon(CharacterIconProvider.CHAR_0021)
            .setBackgroundIcon(DefaultIconProvider.FLAT_SQUARE)
            .build();

    public static SchemaVertexType unsupportedType() {
        return UNSUPPORTED;
    }

    /**
     * Creates a copy of the current SchemaVertexType, and sets a new realm
     * property for this copy.
     *
     * @param type The Type
     * @param realm The realm
     * @param rename Rename the Type with the realm if True, otherwise set to
     * @return
     */
    public static SchemaVertexType copyWithRealm(final SchemaVertexType type, final String realm, final boolean rename) {
        return new SchemaVertexType.Builder(type, rename ? realm : null)
                .setProperty(CyberVertexTypeUtilities.REALM_PROPERTY, realm)
                .build();
    }

}
