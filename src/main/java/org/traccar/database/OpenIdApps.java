/*
 * Copyright 2026 Anton Tananaev (anton@traccar.org)
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
package org.traccar.database;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The applications an OpenID provider says the user may open (claim "apps": name and launch_url each), reduced to
 * what the web app needs for its application menu. Entries without a usable http(s) address are dropped, so the
 * menu never links to anything else (for example a script URL).
 */
public final class OpenIdApps {

    public static final String ATTRIBUTE = "optinexusApps";

    private OpenIdApps() {
    }

    public static List<Map<String, String>> parse(Object claim) {
        List<Map<String, String>> apps = new ArrayList<>();
        if (!(claim instanceof List<?> items)) {
            return apps;
        }
        for (Object item : items) {
            if (item instanceof Map<?, ?> entry
                    && entry.get("name") instanceof String name && !name.isBlank()
                    && entry.get("launch_url") instanceof String url && isWebAddress(url)) {
                Map<String, String> app = new LinkedHashMap<>();
                app.put("name", name.trim());
                app.put("url", url.trim());
                apps.add(app);
            }
        }
        return apps;
    }

    private static boolean isWebAddress(String value) {
        try {
            URI uri = URI.create(value.trim());
            return ("https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme()))
                    && uri.getHost() != null;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
