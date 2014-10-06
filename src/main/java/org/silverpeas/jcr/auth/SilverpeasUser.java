/*
 * Copyright (C) 2000 - 2014 Silverpeas
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the
 * GNU Affero General Public License as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * As a special exception to the terms and conditions of version 3.0 of the GPL, you may
 * redistribute this Program in connection with Free/Libre Open Source Software ("FLOSS")
 * applications as described in Silverpeas's FLOSS exception. You should have received a copy of the
 * text describing the FLOSS exception, and it is also available here:
 * "http://www.silverpeas.org/docs/core/legal/floss_exception.html"
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

package org.silverpeas.jcr.auth;

/**
 * A user in Silverpeas.
 * @author mmoquillon
 */
class SilverpeasUser {

  private String id;
  private String domainId;
  private String login;
  private String encryptedPassword;
  private String domainTablePrefix;
  private String accessLevel;

  private static final String JCR_SYSTEM_LOGIN = "jcr-system";

  private static final SilverpeasUser JCR_SYSTEM_USER = new SilverpeasUser()
      .withId(String.valueOf(JCR_SYSTEM_LOGIN.hashCode()))
      .withDomainId("0")
      .withAccessLevel("S")
      .withLogin(JCR_SYSTEM_LOGIN);

  public static final SilverpeasUser asJcrSystemUser() {
    return JCR_SYSTEM_USER;
  }

  public String getId() {
    return id;
  }

  public SilverpeasUser withId(final String id) {
    this.id = id;
    return this;
  }

  public String getDomainId() {
    return domainId;
  }

  public SilverpeasUser withDomainId(final String domainId) {
    this.domainId = domainId;
    return this;
  }

  public String getLogin() {
    return login;
  }

  public SilverpeasUser withLogin(final String login) {
    this.login = login;
    return this;
  }

  public String getEncryptedPassword() {
    return encryptedPassword;
  }

  public SilverpeasUser withEncryptedPassword(final String encryptedPassword) {
    this.encryptedPassword = encryptedPassword;
    return this;
  }

  public String getDomainTablePrefix() {
    return domainTablePrefix;
  }

  public SilverpeasUser withDomainTablePrefix(final String domainTablePrefix) {
    this.domainTablePrefix = domainTablePrefix;
    return this;
  }

  public String getAccessLevel() {
    return accessLevel;
  }

  public SilverpeasUser withAccessLevel(final String accessLevel) {
    this.accessLevel = accessLevel;
    return this;
  }

  public boolean isJcrSystemUser() {
    return this == JCR_SYSTEM_USER;
  }

  public boolean mustBeAuthenticated() {
    return this != JCR_SYSTEM_USER;
  }
}
