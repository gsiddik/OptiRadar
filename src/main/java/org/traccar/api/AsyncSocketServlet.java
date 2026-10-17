/*
 * Copyright 2015 - 2025 Anton Tananaev (anton@traccar.org)
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
package org.traccar.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.jetty.ee10.websocket.server.JettyWebSocketServlet;
import org.eclipse.jetty.ee10.websocket.server.JettyWebSocketServletFactory;
import org.traccar.api.security.LoginService;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.governance.Catalog;
import org.traccar.governance.GovernanceException;
import org.traccar.governance.GovernanceService;
import org.traccar.governance.GovernedPrincipal;
import org.traccar.session.ConnectionManager;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutorService;

@Singleton
public class AsyncSocketServlet extends JettyWebSocketServlet {

    private final Config config;
    private final ObjectMapper objectMapper;
    private final ConnectionManager connectionManager;
    private final Storage storage;
    private final LoginService loginService;
    private final GovernanceService governance;
    private final ExecutorService executor;

    @Inject
    public AsyncSocketServlet(
            Config config, ObjectMapper objectMapper, ConnectionManager connectionManager, Storage storage,
            LoginService loginService, GovernanceService governance, ExecutorService executor) {
        this.governance = governance;
        this.executor = executor;
        this.config = config;
        this.objectMapper = objectMapper;
        this.connectionManager = connectionManager;
        this.storage = storage;
        this.loginService = loginService;
    }

    @Override
    public void configure(JettyWebSocketServletFactory factory) {
        factory.setIdleTimeout(Duration.ofMillis(config.getLong(Keys.WEB_TIMEOUT)));
        factory.setCreator((req, resp) -> {
            Long userId = null;
            List<String> tokens = req.getParameterMap().get("token");
            if (tokens != null && !tokens.isEmpty()) {
                String token = tokens.iterator().next();
                try {
                    userId = loginService.login(token).getUser().getId();
                } catch (StorageException | GeneralSecurityException | IOException e) {
                    throw new RuntimeException(e);
                }
            } else {
                try {
                    // Same checks as every other session request: origin, expiry, account enabled and a session
                    // the OpenID provider has not ended.
                    var result = loginService.login(req.getHttpServletRequest());
                    userId = result != null ? result.getUser().getId() : null;
                } catch (StorageException | SecurityException e) {
                    userId = null;
                }
            }
            if (userId == null) {
                return null;
            }
            if (!governance.enabled()) {
                return new AsyncSocket(objectMapper, connectionManager, storage, userId);
            }
            try {
                // The live feed is a feature of its own: it needs the permission and the tenant's entitlement.
                GovernedPrincipal principal = governance.principal(userId);
                governance.require(principal, List.of(Catalog.LIVE_VIEW));
                return new AsyncSocket(objectMapper, connectionManager, storage, userId, governance, executor,
                        governance.context(principal));
            } catch (GovernanceException e) {
                try {
                    resp.sendError(e.getStatus() == 503 ? 503 : 403, e.getCode());
                } catch (IOException ignored) {
                    // the connection is gone; nothing to tell
                }
                return null;
            }
        });
    }

}
