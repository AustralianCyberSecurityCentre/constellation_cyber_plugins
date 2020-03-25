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
package au.gov.asd.acsc.constellation.dataaccess.cyber.plugins.urlhaus;

import au.gov.asd.tac.constellation.graph.GraphElementType;
import au.gov.asd.tac.constellation.graph.attribute.BooleanObjectAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.IntegerObjectAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.StringAttributeDescription;
import au.gov.asd.tac.constellation.graph.schema.SchemaAttribute;
import au.gov.asd.tac.constellation.graph.schema.SchemaConcept;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.AnalyticConcept;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.openide.util.lookup.ServiceProvider;

@ServiceProvider(service = SchemaConcept.class)
public class URLHausConcept extends SchemaConcept {

    @Override
    public String getName() {
        return "URLHaus";
    }

    public static class VertexAttribute {

        private VertexAttribute() {
            //ignore
        }

        public static final SchemaAttribute HAS_ENTRY = new SchemaAttribute.Builder(GraphElementType.VERTEX, BooleanObjectAttributeDescription.ATTRIBUTE_NAME, "Has URLHaus Entry")
                .setDescription("Has an entry")
                .build();
        public static final SchemaAttribute SPAMHAUS_ENTRY = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Spamhaus Entry")
                .build();
        public static final SchemaAttribute SURBL_ENTRY = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "SURBL Entry")
                .build();
        public static final SchemaAttribute URL_COUNT = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "URLHaus URL Count")
                .build();
    }

    @Override
    public Collection<SchemaAttribute> getSchemaAttributes() {
        final List<SchemaAttribute> schemaAttributes = new ArrayList<>();
        schemaAttributes.add(VertexAttribute.HAS_ENTRY);
        
        return schemaAttributes;
    }

    @Override
    public Set<Class<? extends SchemaConcept>> getParents() {
        final Set<Class<? extends SchemaConcept>> parentSet = new HashSet<>();
        parentSet.add(AnalyticConcept.class);
        return parentSet;
    }

}
