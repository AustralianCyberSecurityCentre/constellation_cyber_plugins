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
import au.gov.asd.tac.constellation.graph.schema.SchemaAttribute;
import au.gov.asd.tac.constellation.graph.schema.SchemaConcept;
import au.gov.asd.tac.constellation.graph.schema.SchemaVertexType;
import au.gov.asd.tac.constellation.visual.icons.AnalyticIconProvider;
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
        public static final SchemaAttribute VHASH = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "vHash")
                .build();
        public static final SchemaAttribute SSDEEP = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "ssdeep")
                .build();
        public static final SchemaAttribute IMPHASH = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "imphash")
                .build();
        public static final SchemaAttribute CATEGORY = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Category")
                .build();
        public static final SchemaAttribute METHOD = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Method")
                .build();
        public static final SchemaAttribute VERSION = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Version")
                .build();
        public static final SchemaAttribute AV_ENGINE = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "AV Engine")
                .build();
        public static final SchemaAttribute AV_HITS = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "AV Hits")
                .build();
        public static final SchemaAttribute FAILURE_COUNT = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "Failure Count")
                .build();
        public static final SchemaAttribute CONFIRMED_TIMEOUT_COUNT = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "Confirmed Timeout Count")
                .build();
        public static final SchemaAttribute HARMLESS_COUNT = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "Harmless Count")
                .build();
        public static final SchemaAttribute MALICIOUS_COUNT = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "Malicious Count")
                .build();
        public static final SchemaAttribute SUSPICIOUS_COUNT = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "Suspicious Count")
                .build();
        public static final SchemaAttribute TIMEOUT_COUNT = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "Timeout Count")
                .build();
        public static final SchemaAttribute TYPE_UNSUPPORTED_COUNT = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "Type unsupported Count")
                .build();
        public static final SchemaAttribute UNDETECTED_COUNT = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "Undetected Count")
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
        schemaAttributes.add(VertexAttribute.CATEGORY);
        schemaAttributes.add(VertexAttribute.METHOD);
        schemaAttributes.add(VertexAttribute.RESULT);
        schemaAttributes.add(VertexAttribute.VERSION);
        schemaAttributes.add(VertexAttribute.AV_ENGINE);
        schemaAttributes.add(VertexAttribute.AV_HITS);
        schemaAttributes.add(VertexAttribute.VHASH);
        schemaAttributes.add(VertexAttribute.SSDEEP);
        schemaAttributes.add(VertexAttribute.IMPHASH);
        schemaAttributes.add(VertexAttribute.CONFIRMED_TIMEOUT_COUNT);
        schemaAttributes.add(VertexAttribute.FAILURE_COUNT);
        schemaAttributes.add(VertexAttribute.HARMLESS_COUNT);
        schemaAttributes.add(VertexAttribute.MALICIOUS_COUNT);
        schemaAttributes.add(VertexAttribute.SUSPICIOUS_COUNT);
        schemaAttributes.add(VertexAttribute.TIMEOUT_COUNT);
        schemaAttributes.add(VertexAttribute.TYPE_UNSUPPORTED_COUNT);
        schemaAttributes.add(VertexAttribute.UNDETECTED_COUNT);
        return Collections.unmodifiableCollection(schemaAttributes);
    }
}
