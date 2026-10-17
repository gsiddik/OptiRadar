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
package org.traccar.model;

import org.traccar.storage.StorageName;

import java.util.Date;

/**
 * The OpenID identity (issuer + subject) an OptiRadar account belongs to. The subject is the provider's stable id of
 * the person; the email is only a profile attribute and can change or be reused. An identity belongs to one account
 * and an account has one identity per issuer (both enforced by unique constraints).
 */
@StorageName("tc_openid_identities")
public class OpenIdIdentity extends BaseModel {

    public static final String VIA_NEW_ACCOUNT = "new-account";
    public static final String VIA_LEGACY_EMAIL = "legacy-email";

    private long userId;

    public long getUserId() {
        return userId;
    }

    public void setUserId(long userId) {
        this.userId = userId;
    }

    private String issuer;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    private String subject;

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    private String email;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    private String linkedVia;

    public String getLinkedVia() {
        return linkedVia;
    }

    public void setLinkedVia(String linkedVia) {
        this.linkedVia = linkedVia;
    }

    private Date createdAt;

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    private Date lastLoginAt;

    public Date getLastLoginAt() {
        return lastLoginAt;
    }

    public void setLastLoginAt(Date lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

}
