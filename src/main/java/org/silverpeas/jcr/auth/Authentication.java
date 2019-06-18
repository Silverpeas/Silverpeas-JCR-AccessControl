/*
 * Copyright (C) 2000 - 2019 Silverpeas
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * As a special exception to the terms and conditions of version 3.0 of
 * the GPL, you may redistribute this Program in connection with Free/Libre
 * Open Source Software ("FLOSS") applications as described in Silverpeas's
 * FLOSS exception.  You should have received a copy of the text describing
 * the FLOSS exception, and it is also available here:
 * "http://www.silverpeas.org/legal/licensing"
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.silverpeas.jcr.auth;

import javax.jcr.Credentials;
import java.security.Principal;

/**
 * A service for authenticating a user that want to access the JCR repository used by Silverpeas.
 * The authentication wraps all the mechanism to perform the authentication process itself.
 * @author mmoquillon
 */
public interface Authentication {

  /**
   * Authenticates a user by its credentials.
   * @param credentials the credentials of a user.
   * @return the principal of the authenticated user or null if the specified credentials aren't
   * supported by this authentication.
   * @throws AuthenticationException if the authentication fails.
   */
  public Principal authenticate(final Credentials credentials) throws AuthenticationException;

}
