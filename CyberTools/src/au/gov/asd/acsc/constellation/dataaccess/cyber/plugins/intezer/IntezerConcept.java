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

import au.gov.asd.tac.constellation.graph.GraphElementType;
import au.gov.asd.tac.constellation.graph.attribute.BooleanObjectAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.IntegerObjectAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.StringAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.ZonedDateTimeAttributeDescription;
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
public class IntezerConcept extends SchemaConcept {

    @Override
    public String getName() {
        return "Intezer";
    }

    @Override
    public Set<Class<? extends SchemaConcept>> getParents() {
        final Set<Class<? extends SchemaConcept>> parentSet = new HashSet<>();
        return Collections.unmodifiableSet(parentSet);
    }

    public static class VertexAttribute {

        public static final SchemaAttribute FAMILY_TYPE = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Family Type")
                .build();
        
        public static final SchemaAttribute VERDICT = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Verdict")
                .build();
        
        public static final SchemaAttribute ANALYSIS_TIME = new SchemaAttribute.Builder(GraphElementType.VERTEX, ZonedDateTimeAttributeDescription.ATTRIBUTE_NAME, "Analysis Time")
                .build();
        
    }

    public static class VertexType {

        public static final SchemaVertexType PROCESS = new SchemaVertexType.Builder("Process")
                .setForegroundIcon(AnalyticIconProvider.MICROPROCESSOR)
                .build();
        
        public static final SchemaVertexType CODE_FAMILY = new SchemaVertexType.Builder("Code Family")
                .setForegroundIcon(AnalyticIconProvider.GROUP)
                .build();
        
    }

    @Override
    public List<SchemaVertexType> getSchemaVertexTypes() {
        final List<SchemaVertexType> schemaVertexTypes = new ArrayList<>();
        schemaVertexTypes.add(VertexType.PROCESS);
        schemaVertexTypes.add(VertexType.CODE_FAMILY);
        
        return schemaVertexTypes;
    }

    @Override
    public Collection<SchemaAttribute> getSchemaAttributes() {
        final List<SchemaAttribute> schemaAttributes = new ArrayList<>();
        schemaAttributes.add(VertexAttribute.FAMILY_TYPE);
        schemaAttributes.add(VertexAttribute.VERDICT);
        schemaAttributes.add(VertexAttribute.ANALYSIS_TIME);
        return Collections.unmodifiableCollection(schemaAttributes);
    }
}
