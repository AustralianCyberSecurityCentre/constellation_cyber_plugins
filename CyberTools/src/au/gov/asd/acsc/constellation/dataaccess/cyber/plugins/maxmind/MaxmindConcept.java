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

import au.gov.asd.tac.constellation.graph.GraphElementType;
import au.gov.asd.tac.constellation.graph.attribute.BooleanObjectAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.StringAttributeDescription;
import au.gov.asd.tac.constellation.graph.schema.attribute.SchemaAttribute;
import au.gov.asd.tac.constellation.graph.schema.concept.SchemaConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.openide.util.lookup.ServiceProvider;

@ServiceProvider(service = SchemaConcept.class)
public class MaxmindConcept extends SchemaConcept {

    @Override
    public String getName() {
        return "Maxmind";
    }

    public static class VertexAttribute {

        private VertexAttribute() {
            //ignore
        }

        public static final SchemaAttribute CONNECTION_TYPE = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Connection Type")
                .setDescription("Connection Type")
                .build();

        public static final SchemaAttribute IS_ANONYMOUS = new SchemaAttribute.Builder(GraphElementType.VERTEX, BooleanObjectAttributeDescription.ATTRIBUTE_NAME, "is Anonymous")
                .setDescription("is Anonymous")
                .build();

        public static final SchemaAttribute IS_ANONYMOUS_PROXY = new SchemaAttribute.Builder(GraphElementType.VERTEX, BooleanObjectAttributeDescription.ATTRIBUTE_NAME, "is Anonymous Proxy")
                .setDescription("is Anonymous Proxy")
                .build();
        public static final SchemaAttribute IS_ANONYMOUS_VPN = new SchemaAttribute.Builder(GraphElementType.VERTEX, BooleanObjectAttributeDescription.ATTRIBUTE_NAME, "is Anonymous VPN")
                .setDescription("is Anonymous VPN")
                .build();

        public static final SchemaAttribute IS_HOSTING_PROVIDER = new SchemaAttribute.Builder(GraphElementType.VERTEX, BooleanObjectAttributeDescription.ATTRIBUTE_NAME, "is Hosting Provider")
                .setDescription("is Hosting Provider")
                .build();

        public static final SchemaAttribute IS_LEGITIMATE_PROXY = new SchemaAttribute.Builder(GraphElementType.VERTEX, BooleanObjectAttributeDescription.ATTRIBUTE_NAME, "is Legitimate Proxy")
                .setDescription("is Legitimate Proxy")
                .build();

        public static final SchemaAttribute IS_PUBLIC_PROXY = new SchemaAttribute.Builder(GraphElementType.VERTEX, BooleanObjectAttributeDescription.ATTRIBUTE_NAME, "is Public Proxy")
                .setDescription("is Public Proxy")
                .build();

        public static final SchemaAttribute IS_TOR_EXIT_NODE = new SchemaAttribute.Builder(GraphElementType.VERTEX, BooleanObjectAttributeDescription.ATTRIBUTE_NAME, "is Tor Exit Node")
                .setDescription("is Tor Exit Node")
                .build();

        public static final SchemaAttribute DOMAIN = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Domain")
                .setDescription("Domain")
                .build();

        public static final SchemaAttribute ISP = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "ISP")
                .setDescription("ISP")
                .build();

        public static final SchemaAttribute ORGANISATION = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Organisation")
                .setDescription("Organisation")
                .build();

        public static final SchemaAttribute USER_TYPE = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "User Type")
                .setDescription("User Type")
                .build();

        public static final SchemaAttribute ASN_ORGANISATION = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "ASN Organisation")
                .setDescription("ASN Organisation")
                .build();

        public static final SchemaAttribute ASN = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "ASN")
                .setDescription("ASN")
                .build();

        public static final SchemaAttribute POSTAL = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Postal")
                .setDescription("Post code")
                .build();

        public static final SchemaAttribute SUBDIVISION = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Subdivision")
                .setDescription("Subdivision or suburb")
                .build();

    }

    @Override
    public Collection<SchemaAttribute> getSchemaAttributes() {
        final List<SchemaAttribute> schemaAttributes = new ArrayList<>();
        schemaAttributes.add(VertexAttribute.CONNECTION_TYPE);
        schemaAttributes.add(VertexAttribute.IS_ANONYMOUS);
        schemaAttributes.add(VertexAttribute.IS_ANONYMOUS_PROXY);
        schemaAttributes.add(VertexAttribute.IS_ANONYMOUS_VPN);
        schemaAttributes.add(VertexAttribute.IS_HOSTING_PROVIDER);
        schemaAttributes.add(VertexAttribute.IS_LEGITIMATE_PROXY);
        schemaAttributes.add(VertexAttribute.IS_PUBLIC_PROXY);
        schemaAttributes.add(VertexAttribute.IS_TOR_EXIT_NODE);
        schemaAttributes.add(VertexAttribute.DOMAIN);
        schemaAttributes.add(VertexAttribute.ISP);
        schemaAttributes.add(VertexAttribute.ORGANISATION);
        schemaAttributes.add(VertexAttribute.USER_TYPE);
        schemaAttributes.add(VertexAttribute.ASN_ORGANISATION);
        schemaAttributes.add(VertexAttribute.ASN);
        schemaAttributes.add(VertexAttribute.SUBDIVISION);
        schemaAttributes.add(VertexAttribute.POSTAL);
        return schemaAttributes;
    }

    @Override
    public Set<Class<? extends SchemaConcept>> getParents() {
        final Set<Class<? extends SchemaConcept>> parentSet = new HashSet<>();
        parentSet.add(AnalyticConcept.class);
        return parentSet;
    }

}
