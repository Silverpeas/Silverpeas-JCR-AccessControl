/*
 * Copyright (C) 2000 - 2017 Silverpeas
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

import org.silverpeas.jcr.auth.encryption.PasswordEncryption;
import org.silverpeas.jcr.auth.encryption.PasswordEncryptionFactory;

import javax.jcr.Credentials;
import javax.jcr.SimpleCredentials;
import java.security.Principal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.MessageFormat;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A simple authentication by login/password. It accesses the Silverpeas database to fetch the
 * encrypted password of the user in order to validate the one passing in the credentials. For
 * doing, the domain to which the user belongs has to be backed into a the Silverpeas database and
 * then it doesn't support domains backed by a LDAP directory or any data sources other than
 * the Silverpeas database.
 * This mechanism is mainly used to access JCR outside the context of Silverpeas; for example by
 * using an external service (like Crash). For a better authentication mechanism, we strongly
 * recommend to use the one based upon the volatile security tokens.
 * @author mmoquillon
 */
public class SQLSimpleAuthentication extends AbstractAuthentication {

  private static final String SELECT_DOMAIN_TABLE =
      "select propfilename, classname from st_domain where id = ?";

  private static final String SELECT_USER_DATA =
      "select du.id as id, du.password as password, u.accesslevel as accesslevel from " +
          "{0}_user du left join st_user u on du.id = u.id where du.login = ? and u.state = ''VALID''";

  /**
   * Authenticates a user by its credentials.
   * @param credentials the simple credentials of a user. If the credentials aren't with the
   * expected type, then null is returned.
   * @return the principal of the authenticated user or null if the credentials are not supported
   * by this authentication mechanism.
   * @throws AuthenticationException if the authentication fails.
   */
  @Override
  public Principal authenticate(final Credentials credentials) throws AuthenticationException {
    Principal principal = null;
    if (credentials instanceof SimpleCredentials) {
      principal = authenticate((SimpleCredentials) credentials);
    }
    return principal;
  }

  /**
   * Authenticates a user with the specified simple credentials.
   * <p>
   * The authentication mechanism expects the user identifier in the credentials is in the form of
   * USER_LOGIN'@'SILVERPEAS_DOMAIN where USER_LOGIN is the login of the user to sign in Silverpeas
   * and the SILVERPEAS_DOMAIN is the identifier of the domain in Silverpeas to which the user
   * belongs.
   * </p>
   * @param credentials the simple credentials of a user.
   * @return the principal of the user or null if either the credentials of the user aren't taken
   * into account by this authentication mechanism or the credentials of the user aren't full
   * stored
   * into the data source of Silverpeas.
   * @throws AuthenticationException if the authentication fails (the pair identifier/password
   * isn't valid or no user matches the login and the domain specified in the credentials).
   */
  public Principal authenticate(SimpleCredentials credentials) throws AuthenticationException {
    Principal principal = null;
    String[] userIdParts = fetchUserIdParts(credentials.getUserID());
    if (userIdParts != null && userIdParts.length == 2) {
      String login = userIdParts[0];
      String domainId = userIdParts[1];
      SilverpeasUser user = getSilverpeasUserByDomain(login, domainId);
      if (user != null) {
        if (user.mustBeAuthenticated()) {
          PasswordEncryption encryption = PasswordEncryptionFactory.getFactory()
              .getPasswordEncryption(user.getEncryptedPassword());
          try {
            encryption.check(new String(credentials.getPassword()), user.getEncryptedPassword());
          } catch (AssertionError error) {
            throw new AuthenticationException(error.getMessage());
          }
        }
        principal = getSilverpeasUserPrincipal(user);
      } else {
        throw new AuthenticationException("No user matching the login " + login +
            " and the domain identifier " + domainId);
      }
    }
    return principal;
  }

  /**
   * Gets information about the user matching the specified login for the specified domain
   * identifier. The domain should be backed by a database as the user is first identified within
   * its domain before getting any information about him. Among the information, there is the
   * encrypted password with which the authentication can be performed.
   * @param login the user login.
   * @param domainId the unique identifier of the domain to which the user belongs.
   * @return the user matching the specified login and domain or null.
   */
  private SilverpeasUser getSilverpeasUserByDomain(final String login, final String domainId) {
    SilverpeasUser user = SilverpeasUser.asJcrSystemUser();
    if (!user.getLogin().equals(login) || !user.getDomainId().equals(domainId)) {
      user = null;
      try (Connection connection = openConnectionToDataSource();
           PreparedStatement domainStatement = connection.prepareStatement(SELECT_DOMAIN_TABLE)) {
        domainStatement.setInt(1, Integer.parseInt(domainId));
        try (ResultSet domainResultSet = domainStatement.executeQuery()) {
          if (domainResultSet.next()) {
            String className = domainResultSet.getString("classname");
            if (className != null && (className.toLowerCase().endsWith("sqldriver") ||
                className.toLowerCase().endsWith("silverpeasdomaindriver"))) {
              String domainName = fetchDomainNameFrom(domainResultSet.getString("propfilename"));
              String sqlUserData = computeUserDataSQLQueryFor(domainName);
              try (PreparedStatement userStatement = connection.prepareStatement(sqlUserData)) {
                userStatement.setString(1, login);
                try (ResultSet userResultSet = userStatement.executeQuery()) {
                  if (userResultSet.next()) {
                    user = new SilverpeasUser().withId(userResultSet.getString("id"))
                        .withDomainId(domainId)
                        .withAccessLevel(userResultSet.getString("accesslevel"))
                        .withEncryptedPassword(userResultSet.getString("password"));
                  }
                }
              }
            }
          }
        }
      } catch (SQLException e) {
        Logger.getLogger(getClass().getSimpleName()).log(Level.SEVERE, e.getMessage(), e);
      }
    }
    return user;
  }

  private String fetchDomainNameFrom(String propFileName) {
    int lastSepIndex = propFileName.lastIndexOf(".");
    return (lastSepIndex > 0 ? propFileName.substring(lastSepIndex + 1).toLowerCase() : null);
  }

  private String computeUserDataSQLQueryFor(String tableName) {
    return MessageFormat.format(SELECT_USER_DATA, tableName);
  }
}
