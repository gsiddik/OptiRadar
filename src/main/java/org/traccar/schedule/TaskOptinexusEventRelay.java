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
package org.traccar.schedule;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.database.OptinexusEventRelay;

import jakarta.inject.Inject;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Periodically hands the events waiting in the outbox to OptiNexus. Runs on one server only when several share the
 * database, and not at all unless optinexus.events.enable is set.
 */
public class TaskOptinexusEventRelay extends SingleScheduleTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(TaskOptinexusEventRelay.class);

    private final OptinexusEventRelay relay;
    private final boolean enabled;
    private final long interval;

    @Inject
    public TaskOptinexusEventRelay(Config config, OptinexusEventRelay relay) {
        this.relay = relay;
        this.enabled = config.getBoolean(Keys.OPTINEXUS_EVENTS_ENABLE);
        this.interval = config.getLong(Keys.OPTINEXUS_EVENTS_INTERVAL);
    }

    @Override
    public void schedule(ScheduledExecutorService executor) {
        if (!enabled) {
            return;
        }
        if (!relay.configured()) {
            LOGGER.warn("optinexus.events.enable is set but optinexus.baseUrl, optinexus.clientId or "
                    + "optinexus.clientSecret is missing: events are recorded but not delivered");
            return;
        }
        executor.scheduleWithFixedDelay(this, interval, interval, TimeUnit.SECONDS);
    }

    @Override
    public void run() {
        try {
            var result = relay.relay();
            if (result.delivered() + result.retrying() + result.failed() > 0) {
                LOGGER.info("OptiNexus events: {} delivered, {} to retry, {} failed",
                        result.delivered(), result.retrying(), result.failed());
            }
        } catch (Exception e) {
            LOGGER.warn("OptiNexus event delivery error", e);
        }
    }

}
