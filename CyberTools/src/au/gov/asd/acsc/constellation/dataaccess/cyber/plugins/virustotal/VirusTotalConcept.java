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

import au.gov.asd.tac.constellation.graph.GraphElementType;
import au.gov.asd.tac.constellation.graph.attribute.BooleanObjectAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.IntegerObjectAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.StringAttributeDescription;
import au.gov.asd.tac.constellation.graph.schema.attribute.SchemaAttribute;
import au.gov.asd.tac.constellation.graph.schema.concept.SchemaConcept;
import au.gov.asd.tac.constellation.graph.schema.type.SchemaVertexType;
import au.gov.asd.tac.constellation.utilities.icon.AnalyticIconProvider;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.openide.util.lookup.ServiceProvider;

@ServiceProvider(service = SchemaConcept.class)
public class VirusTotalConcept extends SchemaConcept {

    @Override
    public String getName() {
        return "Virus Total";
    }

    @Override
    public Set<Class<? extends SchemaConcept>> getParents() {
        final Set<Class<? extends SchemaConcept>> parentSet = new HashSet<>();
        return Collections.unmodifiableSet(parentSet);
    }

    public static class VertexAttribute {

        public static final SchemaAttribute HAS_VIRUS_TOTAL_ENTRY = new SchemaAttribute.Builder(GraphElementType.VERTEX, BooleanObjectAttributeDescription.ATTRIBUTE_NAME, "Has Virus Total Entry")
                .build();
        public static final SchemaAttribute DETECTED = new SchemaAttribute.Builder(GraphElementType.VERTEX, BooleanObjectAttributeDescription.ATTRIBUTE_NAME, "Detected")
                .build();
        public static final SchemaAttribute RESULT = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Result")
                .build();
        public static final SchemaAttribute VERSION = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Version")
                .build();
        public static final SchemaAttribute AV_ENGINE = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "AV Engine")
                .build();
        public static final SchemaAttribute AV_HITS = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "AV Hits")
                .build();
    }

    public static class VertexType {

        public static final SchemaVertexType AV_RESULT = new SchemaVertexType.Builder("AV Result")
                .setForegroundIcon(AnalyticIconProvider.FINGERPRINT)
                .build();
    }

    @Override
    public List<SchemaVertexType> getSchemaVertexTypes() {
        final List<SchemaVertexType> schemaVertexTypes = new ArrayList<>();
        schemaVertexTypes.add(VertexType.AV_RESULT);
        return schemaVertexTypes;
    }

    @Override
    public Collection<SchemaAttribute> getSchemaAttributes() {
        final List<SchemaAttribute> schemaAttributes = new ArrayList<>();
        schemaAttributes.add(VertexAttribute.HAS_VIRUS_TOTAL_ENTRY);
        schemaAttributes.add(VertexAttribute.DETECTED);
        schemaAttributes.add(VertexAttribute.RESULT);
        schemaAttributes.add(VertexAttribute.VERSION);
        schemaAttributes.add(VertexAttribute.AV_ENGINE);
        schemaAttributes.add(VertexAttribute.AV_HITS);
        return Collections.unmodifiableCollection(schemaAttributes);
    }
}
