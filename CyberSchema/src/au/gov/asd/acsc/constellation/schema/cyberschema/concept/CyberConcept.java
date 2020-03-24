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

import au.gov.asd.tac.constellation.graph.GraphElementType;
import au.gov.asd.tac.constellation.graph.attribute.IntegerObjectAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.LongObjectAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.StringAttributeDescription;
import au.gov.asd.tac.constellation.graph.schema.SchemaAttribute;
import au.gov.asd.tac.constellation.graph.schema.SchemaConcept;
import au.gov.asd.tac.constellation.graph.schema.SchemaVertexType;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.AnalyticConcept;

import au.gov.asd.tac.constellation.visual.icons.AnalyticIconProvider;
import au.gov.asd.tac.constellation.visual.icons.CharacterIconProvider;
import au.gov.asd.tac.constellation.visual.icons.UserInterfaceIconProvider;
import au.gov.asd.acsc.constellation.schema.cyberschema.icons.CyberIconProvider;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.openide.util.lookup.ServiceProvider;

@ServiceProvider(service = SchemaConcept.class)
public class CyberConcept extends SchemaConcept {

    @Override
    public String getName() {
        return "Cyber";
    }

    @Override
    public Set<Class<? extends SchemaConcept>> getParents() {
        final Set<Class<? extends SchemaConcept>> parentSet = new HashSet<>();
        parentSet.add(AnalyticConcept.class);
        return Collections.unmodifiableSet(parentSet);
    }

    public static class VertexType {

        public static final SchemaVertexType NETWORKBASED_TYPES = new SchemaVertexType.Builder("Network Based Types")
                .setForegroundIcon(AnalyticIconProvider.SHIELD)
                .build();

        public static final SchemaVertexType BANNER = new SchemaVertexType.Builder("Banner")
                .setForegroundIcon(AnalyticIconProvider.CHAT)
                .setSuperType(VertexType.NETWORKBASED_TYPES)
                .build();

        public static final SchemaVertexType CVE = new SchemaVertexType.Builder("CVE")
                .setForegroundIcon(AnalyticIconProvider.INVADER)
                .setSuperType(VertexType.NETWORKBASED_TYPES)
                .build();

        public static final SchemaVertexType HOSTBASED_TYPES = new SchemaVertexType.Builder("Host Based Types")
                .setForegroundIcon(AnalyticIconProvider.SHIELD)
                .build();

        public static final SchemaVertexType PROJECT = new SchemaVertexType.Builder("Project")
                .setSuperType(VertexType.HOSTBASED_TYPES)
                .setForegroundIcon(UserInterfaceIconProvider.SEARCH)
                .build();

        public static final SchemaVertexType FILE = new SchemaVertexType.Builder("File")
                .setSuperType(VertexType.HOSTBASED_TYPES)
                .setForegroundIcon(UserInterfaceIconProvider.SEARCH)
                .build();

        public static final SchemaVertexType SIGNATURE = new SchemaVertexType.Builder("Signature")
                .setForegroundIcon(AnalyticIconProvider.FINGERPRINT)
                .setSuperType(VertexType.HOSTBASED_TYPES)
                .build();

        public static final SchemaVertexType INCIDENT_TYPE = new SchemaVertexType.Builder("Cyber Incident Types")
                .setForegroundIcon(AnalyticIconProvider.SHIELD)
                .build();

        public static final SchemaVertexType INCIDENT = new SchemaVertexType.Builder("Cyber Incident")
                .setSuperType(VertexType.INCIDENT_TYPE)
                .setForegroundIcon(AnalyticIconProvider.SHIELD)
                .build();

        public static final SchemaVertexType INTRUSION_SET = new SchemaVertexType.Builder("Intrusion Set")
                .setSuperType(VertexType.INCIDENT_TYPE)
                .setForegroundIcon(AnalyticIconProvider.GROUP)
                .build();
        public static final SchemaVertexType OBSERVATION = new SchemaVertexType.Builder("Observation")
                .setSuperType(INCIDENT_TYPE)
                .setForegroundIcon(AnalyticIconProvider.CAMERA)
                .build();

        public static final SchemaVertexType ASSET = new SchemaVertexType.Builder("Asset")
                .setSuperType(INCIDENT_TYPE)
                .setForegroundIcon(AnalyticIconProvider.BUILDING)
                .build();

        public static final SchemaVertexType CYBER_EVENT = new SchemaVertexType.Builder("Cyber Event")
                .setSuperType(INCIDENT_TYPE)
                .setForegroundIcon(AnalyticIconProvider.LIGHTNING)
                .build();

        public static final SchemaVertexType ALERT_SOURCE = new SchemaVertexType.Builder("Alert Source")
                .setSuperType(INCIDENT_TYPE)
                .setForegroundIcon(AnalyticIconProvider.FINGERPRINT)
                .build();
        
        public static final SchemaVertexType JA3 = new SchemaVertexType.Builder("JA3")
                .setForegroundIcon(AnalyticIconProvider.SIGNAL)
                .build();

        public static final SchemaVertexType FEATURE = new SchemaVertexType.Builder("Feature")
                .setForegroundIcon(CyberIconProvider.FEATURE)
                .build();

        public static final SchemaVertexType STRING = new SchemaVertexType.Builder("String")
                .setForegroundIcon(CharacterIconProvider.CHAR_0065)
                .build();

    }

    public static class TransactionAttribute {

        private TransactionAttribute() {
            // ignore
        }

        public static final SchemaAttribute OFFSET = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, StringAttributeDescription.ATTRIBUTE_NAME, "Offset")
                .setDescription("Offset")
                .build();

        public static final SchemaAttribute DESCRIPTION = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, StringAttributeDescription.ATTRIBUTE_NAME, "Description")
                .setDescription("Description")
                .build();
        public static final SchemaAttribute CONFIDENCE = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, StringAttributeDescription.ATTRIBUTE_NAME, "Confidence")
                .setDescription("Confidence")
                .build();

        public static final SchemaAttribute SRC_PORTS = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, StringAttributeDescription.ATTRIBUTE_NAME, "Source Ports")
                .setDescription("Source Ports")
                .build();

        public static final SchemaAttribute DST_PORTS = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, StringAttributeDescription.ATTRIBUTE_NAME, "Destination Ports")
                .setDescription("Destination Ports")
                .build();

        public static final SchemaAttribute OCTETS = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, LongObjectAttributeDescription.ATTRIBUTE_NAME, "Octets")
                .setDescription("Octets")
                .build();

        public static final SchemaAttribute FLOW_COUNT = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, LongObjectAttributeDescription.ATTRIBUTE_NAME, "Flow Count")
                .setDescription("Flow Count")
                .build();

        public static final SchemaAttribute PACKETS = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, LongObjectAttributeDescription.ATTRIBUTE_NAME, "Packets")
                .setDescription("Packets")
                .build();

        public static final SchemaAttribute PROTOCOL = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, StringAttributeDescription.ATTRIBUTE_NAME, "Protocol")
                .setDescription("Protocol")
                .build();

        public static final SchemaAttribute FLAGS = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, StringAttributeDescription.ATTRIBUTE_NAME, "Flags")
                .setDescription("Flags")
                .build();
    }

    @Override
    public List<SchemaVertexType> getSchemaVertexTypes() {
        final List<SchemaVertexType> schemaVertexTypes = new ArrayList<>();
        schemaVertexTypes.add(VertexType.HOSTBASED_TYPES);
        schemaVertexTypes.add(VertexType.INCIDENT_TYPE);
        schemaVertexTypes.add(VertexType.FILE);
        schemaVertexTypes.add(VertexType.CVE);
        schemaVertexTypes.add(VertexType.INCIDENT);
        schemaVertexTypes.add(VertexType.INTRUSION_SET);
        schemaVertexTypes.add(VertexType.OBSERVATION);
        schemaVertexTypes.add(VertexType.CYBER_EVENT);
        schemaVertexTypes.add(VertexType.ALERT_SOURCE);
        schemaVertexTypes.add(VertexType.JA3);
        schemaVertexTypes.add(VertexType.ASSET);
        schemaVertexTypes.add(VertexType.PROJECT);
        schemaVertexTypes.add(VertexType.BANNER);
        schemaVertexTypes.add(VertexType.SIGNATURE);
        schemaVertexTypes.add(VertexType.FEATURE);
        schemaVertexTypes.add(VertexType.STRING);
        return Collections.unmodifiableList(schemaVertexTypes);
    }

    public static class VertexAttribute {

        public static final SchemaAttribute OBSERVATION_TYPE = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Observation Type")
                .setDescription("Observation Type")
                .build();

        public static final SchemaAttribute INCIDENT_ID = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Incident Id")
                .setDescription("Incident Id")
                .build();

        public static final SchemaAttribute INCIDENT_TYPE = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Incident Type")
                .setDescription("Incident Type")
                .build();

        public static final SchemaAttribute NATIONALITY = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Nationality")
                .setDescription("Nationality")
                .build();
        
        public static final SchemaAttribute OPERATING_SYSTEM = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Operating System")
                .setDescription("Operating System")
                .build();

        public static final SchemaAttribute COUNT = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "Count")
                .setDescription("Count")
                .build();

        public static final SchemaAttribute FILEFORMAT = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "File Format")
                .setDescription("File Format")
                .build();
        public static final SchemaAttribute FILENAME = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Filename")
                .setDescription("Filename")
                .build();
        public static final SchemaAttribute MD5 = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "MD5")
                .setDescription("MD5 Hash")
                .build();
        public static final SchemaAttribute SHA1 = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "SHA1")
                .setDescription("SHA1 Hash")
                .build();
        public static final SchemaAttribute SHA224 = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "SHA224")
                .setDescription("SHA224 Hash")
                .build();
        public static final SchemaAttribute SHA256 = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "SHA256")
                .setDescription("SHA256 Hash")
                .build();
        public static final SchemaAttribute STATUS = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Status")
                .setDescription("Status")
                .build();
        public static final SchemaAttribute INDUSTRY_TYPE = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Industry Type")
                .setDescription("Industry Type")
                .build();
        public static final SchemaAttribute SIGNATURE_ID = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Signature Id")
                .setDescription("Signature Id")
                .build();
        public static final SchemaAttribute PROTOCOL = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Protocol")
                .setDescription("Protocol")
                .build();
        
        public static final SchemaAttribute CLASSIFICATION = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Classification")
                .setDescription("Classification")
                .build();
        
        public static final SchemaAttribute ACTOR = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Actor")
                .setDescription("Actor")
                .build();
        
        public static final SchemaAttribute CATEGORY = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Category")
                .setDescription("Category")
                .build();
        
        public static final SchemaAttribute TAGS = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Tags")
                .setDescription("Tags")
                .build();
                
        public static final SchemaAttribute FEATURE_COUNT = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "Feature Count")
                .setDescription("Feature Count")
                .build();
        public static final SchemaAttribute DEPTH = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "Depth")
                .setDescription("Depth")
                .build();

        public static final SchemaAttribute SIZE = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "Size")
                .setDescription("Size")
                .build();

    }

    @Override
    public Collection<SchemaAttribute> getSchemaAttributes() {
        final List<SchemaAttribute> attributes = new ArrayList<>();
        attributes.add(VertexAttribute.OBSERVATION_TYPE);
        attributes.add(VertexAttribute.PROTOCOL);
        attributes.add(TransactionAttribute.PROTOCOL);
        attributes.add(VertexAttribute.SIGNATURE_ID);
        attributes.add(VertexAttribute.INCIDENT_ID);
        attributes.add(VertexAttribute.ACTOR);
        attributes.add(VertexAttribute.TAGS);
        attributes.add(VertexAttribute.CATEGORY);
        attributes.add(VertexAttribute.CLASSIFICATION);
        attributes.add(VertexAttribute.OPERATING_SYSTEM);
        attributes.add(VertexAttribute.INCIDENT_TYPE);
        attributes.add(VertexAttribute.STATUS);
        attributes.add(VertexAttribute.NATIONALITY);
        attributes.add(VertexAttribute.INDUSTRY_TYPE);
        attributes.add(VertexAttribute.FILENAME);
        attributes.add(VertexAttribute.FILEFORMAT);
        attributes.add(VertexAttribute.MD5);
        attributes.add(VertexAttribute.COUNT);
        attributes.add(TransactionAttribute.PACKETS);
        attributes.add(TransactionAttribute.OCTETS);
        attributes.add(TransactionAttribute.FLOW_COUNT);
        attributes.add(TransactionAttribute.SRC_PORTS);
        attributes.add(TransactionAttribute.DST_PORTS);
        attributes.add(VertexAttribute.SHA1);
        attributes.add(VertexAttribute.SHA224);
        attributes.add(VertexAttribute.SHA256);
        attributes.add(TransactionAttribute.DESCRIPTION);
        attributes.add(TransactionAttribute.CONFIDENCE);
        attributes.add(VertexAttribute.FEATURE_COUNT);
        attributes.add(VertexAttribute.DEPTH);
        attributes.add(VertexAttribute.SIZE);
        attributes.add(TransactionAttribute.OFFSET);
        attributes.add(TransactionAttribute.FLAGS);
        return Collections.unmodifiableCollection(attributes);
    }
}
