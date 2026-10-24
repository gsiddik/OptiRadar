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
package org.traccar.web;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Lets only the configured origins (and this server itself) show the web app in a frame, so an embedded map cannot be
 * framed by any other site (clickjacking).
 */
public class FrameAncestorsFilter implements Filter {

    private static final Pattern ORIGIN = Pattern.compile("^https?://(\\*\\.)?[A-Za-z0-9.-]+(:[0-9]{1,5})?$");

    private final String policy;

    public FrameAncestorsFilter(String origins) {
        this.policy = policy(origins);
    }

    /** The header value for a space separated list of origins; anything that is not a plain origin is dropped. */
    static String policy(String origins) {
        List<String> allowed = new ArrayList<>();
        allowed.add("'self'");
        if (origins != null) {
            for (String origin : origins.trim().split("\\s+")) {
                if (ORIGIN.matcher(origin).matches()) {
                    allowed.add(origin);
                }
            }
        }
        return "frame-ancestors " + String.join(" ", allowed);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        ((HttpServletResponse) response).setHeader("Content-Security-Policy", policy);
        chain.doFilter(request, response);
    }

}
