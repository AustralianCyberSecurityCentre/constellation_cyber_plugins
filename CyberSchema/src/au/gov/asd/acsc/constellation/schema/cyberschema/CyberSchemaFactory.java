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
package au.gov.asd.acsc.constellation.schema.cyberschema;

import au.gov.asd.acsc.constellation.schema.cyberschema.concept.CyberConcept;
import au.gov.asd.tac.constellation.graph.Graph;
import au.gov.asd.tac.constellation.graph.GraphElementType;
import au.gov.asd.tac.constellation.graph.GraphReadMethods;
import au.gov.asd.tac.constellation.graph.GraphWriteMethods;
import au.gov.asd.tac.constellation.graph.file.GraphDataObject;
import au.gov.asd.tac.constellation.graph.node.GraphNode;
import au.gov.asd.tac.constellation.graph.node.GraphNodeFactory;
import au.gov.asd.tac.constellation.graph.schema.Schema;
import au.gov.asd.tac.constellation.graph.schema.SchemaAttribute;
import au.gov.asd.tac.constellation.graph.schema.SchemaConcept;
import au.gov.asd.tac.constellation.graph.schema.SchemaConcept.ConstellationViewsConcept;
import au.gov.asd.tac.constellation.graph.schema.SchemaFactory;
import au.gov.asd.tac.constellation.graph.schema.SchemaTransactionType;
import au.gov.asd.tac.constellation.graph.schema.SchemaVertexType;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.schema.analyticschema.concept.TemporalConcept;
import au.gov.asd.tac.constellation.graph.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.schema.analyticschema.AnalyticSchemaFactory;
import au.gov.asd.tac.constellation.visual.color.ConstellationColor;
import au.gov.asd.tac.constellation.visual.display.VisualManager;
import au.gov.asd.tac.constellation.visual.icons.AnalyticIconProvider;
import au.gov.asd.tac.constellation.visual.icons.ConstellationIcon;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.openide.util.lookup.ServiceProvider;
import org.openide.windows.TopComponent;

@ServiceProvider(service = SchemaFactory.class, position = Integer.MAX_VALUE - 4)
public class CyberSchemaFactory extends AnalyticSchemaFactory {

    // DO NOT change this!
    public static final String CYBER_SCHEMA_ID = "au.gov.asd.acsc.constellation.schema.cyberschema.CyberSchemaFactory";

    private static final ConstellationIcon ICON_SYMBOL = AnalyticIconProvider.INTERNET;
    private static final ConstellationColor ICON_COLOR = ConstellationColor.LIGHT_GREEN;

    @Override
    public String getName() {
        return CYBER_SCHEMA_ID;
    }

    @Override
    public String getLabel() {
        return "Cyber Graph";
    }

    @Override
    public String getDescription() {
        return "This schema provides support for Cyber concepts";
    }

    @Override
    public ConstellationIcon getIconSymbol() {
        return ICON_SYMBOL;
    }

    @Override
    public ConstellationColor getIconColor() {
        return ICON_COLOR;
    }

    @Override
    public Set<Class<? extends SchemaConcept>> getRegisteredConcepts() {
        final Set<Class<? extends SchemaConcept>> registeredConcepts = new HashSet<>();
        registeredConcepts.add(ConstellationViewsConcept.class);
        registeredConcepts.add(VisualConcept.class);
        registeredConcepts.add(AnalyticConcept.class);
        registeredConcepts.add(CyberConcept.class);
        return Collections.unmodifiableSet(registeredConcepts);
    }

    @Override
    public List<SchemaAttribute> getKeyAttributes(final GraphElementType elementType) {
        final List<SchemaAttribute> keys;
        switch (elementType) {
            case VERTEX:
                keys = Arrays.asList(
                        VisualConcept.VertexAttribute.IDENTIFIER,
                        AnalyticConcept.VertexAttribute.TYPE);
                break;
            case TRANSACTION:
                keys = Arrays.asList(
                        VisualConcept.TransactionAttribute.IDENTIFIER,
                        AnalyticConcept.TransactionAttribute.TYPE,
                        TemporalConcept.TransactionAttribute.DATETIME,
                        AnalyticConcept.TransactionAttribute.SOURCE);
                break;
            default:
                keys = Collections.emptyList();
                break;
        }

        return Collections.unmodifiableList(keys);
    }

    @Override
    public Schema createSchema() {

        return new CyberSchema(this);
    }

    public static class CyberGraphNode extends GraphNode {

        public CyberGraphNode(Graph graph, GraphDataObject graphDataObject, TopComponent topComponent, VisualManager visual) {
            super(graph, graphDataObject, topComponent, visual);

        }
    }

    protected class CyberSchema extends AnalyticSchema implements GraphNodeFactory {

        public CyberSchema(SchemaFactory factory) {
            super(factory);
        }

        @Override
        public void newGraph(final GraphWriteMethods graph) {
            super.newGraph(graph);
        }

        @Override
        public void newVertex(GraphWriteMethods graph, final int vertex) {
            super.newVertex(graph, vertex);
            completeVertex(graph, vertex);
        }

        @Override
        public void completeVertex(GraphWriteMethods graph, final int vertex) {
            super.completeVertex(graph, vertex);

        }

        @Override
        public SchemaVertexType resolveVertexType(String type) {
            return super.resolveVertexType(type);

        }

        @Override
        public void newTransaction(GraphWriteMethods graph, final int transaction) {
            super.newTransaction(graph, transaction);
        }

        @Override
        public void completeTransaction(GraphWriteMethods graph, final int transaction) {
            super.completeTransaction(graph, transaction);
        }

        @Override
        public SchemaTransactionType resolveTransactionType(String type) {
            return super.resolveTransactionType(type);
        }

        @Override
        public int getVertexAliasAttribute(GraphReadMethods graph) {
            return VisualConcept.VertexAttribute.LABEL.get(graph);
        }

        @Override
        public GraphNode createGraphNode(Graph graph, GraphDataObject gdo, TopComponent tc, VisualManager visual) {
            return new CyberGraphNode(graph, gdo, tc, visual);
        }
    }

    private static boolean equals(Object a, Object b) {
        if (a == null) {
            return b == null;
        } else {
            return a.equals(b);
        }
    }
}
