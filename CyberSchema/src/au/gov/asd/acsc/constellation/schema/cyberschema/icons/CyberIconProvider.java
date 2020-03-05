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
package au.gov.asd.acsc.constellation.schema.cyberschema.icons;

import au.gov.asd.tac.constellation.visual.icons.ByteIconData;
import au.gov.asd.tac.constellation.visual.icons.ConstellationIcon;
import au.gov.asd.tac.constellation.visual.icons.ConstellationIconProvider;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.io.IOUtils;
import org.openide.util.lookup.ServiceProvider;

/**
 * An IconProvider defining icons which might be used for analysis purposes.
 *
 */


@ServiceProvider(service = ConstellationIconProvider.class)
public class CyberIconProvider implements ConstellationIconProvider {

    private static ByteIconData loadIcon(String name) {
        try {
            byte[] bytes = IOUtils.toByteArray(CyberIconProvider.class.getResourceAsStream(name));
            return new ByteIconData(bytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new ByteIconData(new byte[0]);
    }

    public static final ConstellationIcon ZIP_FILE = new ConstellationIcon.Builder("Zip File", loadIcon("zip_file.png"))
            .addCategory("Cyber")
            .build();

    public static final ConstellationIcon FEATURE = new ConstellationIcon.Builder("Feature", loadIcon("feature.jpg"))
            .addCategory("Cyber")
            .build();

    public static final ConstellationIcon PDF = new ConstellationIcon.Builder("PDF", loadIcon("pdf.png"))
            .addCategory("Cyber")
            .build();

    public static final ConstellationIcon PE = new ConstellationIcon.Builder("PE", loadIcon("pe.png"))
            .addCategory("Cyber")
            .build();

    public static final ConstellationIcon RAR = new ConstellationIcon.Builder("RAR", loadIcon("rar.png"))
            .addCategory("Cyber")
            .build();

    public static final ConstellationIcon XML = new ConstellationIcon.Builder("XML", loadIcon("xml.PNG"))
            .addCategory("Cyber")
            .build();


    @Override
    public List<ConstellationIcon> getIcons() {
        List<ConstellationIcon> cyberIcons = new ArrayList<>();
        cyberIcons.add(ZIP_FILE);
        cyberIcons.add(FEATURE);
        cyberIcons.add(PDF);
        cyberIcons.add(PE);
        cyberIcons.add(RAR);
        cyberIcons.add(XML);
        return cyberIcons;
    }
}
