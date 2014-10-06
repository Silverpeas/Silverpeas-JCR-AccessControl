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

import org.apache.jackrabbit.api.security.authentication.token.TokenCredentials;
import org.silverpeas.jcr.auth.encryption.PasswordEncryption;
import org.silverpeas.jcr.auth.encryption.PasswordEncryptionFactory;
import org.silverpeas.jcr.jaas.SilverpeasJcrSystemPrincipal;
import org.silverpeas.jcr.jaas.SilverpeasUserPrincipal;
import org.silverpeas.jcr.jaas.SilverpeasUserProfile;

import javax.jcr.Credentials;
import javax.jcr.SimpleCredentials;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import java.security.Principal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.MessageFormat;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Implementation of the {@code Authentication} mechanism by using the data source of Silverpeas.
 * In this implementation, it is expected the credentials of the user to authenticate are stored
 * in the data source. In the case the user has no credentials in the data source of Silverpeas
 * (the user isn't a Silverpeas user or its credentials are stored into a Kerberos or LDAP
 * service), a null principal is then returned meaning the authentication cannot authenticate
 * the specified credentials.
 * @author mmoquillon
 */
public class SilverpeasAuthentication implements Authentication {

  private static final String USERID_TOKEN_ATTRIBUTE = "UserID";

  private static final String SELECT_DOMAIN_TABLE =
      "select propfilename, classname from st_domain where id = ?";

  private static final String SELECT_USER_ROLES =
      "select r.rolename, r.instanceid, c.componentname from st_userrole_user_rel u join " +
          "st_userrole r on u.userroleid = r.id join st_component c on c.id = r.instanceid where " +
          "u.userid = ?";

  private static final String SELECT_USER_DATA =
      "select du.id, du.password, u.accesslevel from {0}_user du left join st_user u on du.id = " +
          "u.id where du.login = ? and u.state = 'VALID'";

  /**
   * Authenticates a user with the specified credentials.
   * <p>
   * It is expected the credentials to be simple ones ({@code javax.jcr.SimpleCredentials}), that
   * is to say credentils with a user identifier and an associated password. The authentication
   * mechanism expects the user identifier is in the form of USER_LOGIN'@'SILVERPEAS_DOMAIN where
   * USER_LOGIN is the login of the user to sign in Silverpeas and the SILVERPEAS_DOMAIN is the
   * name of the domain in Silverpeas to which the user belongs.
   * </p>
   * @param credentials the simple credentials of a user.
   * @return the principal of the user or null if either the credentials of the user aren't taken
   * into account by this authentication mechanism or the credentials of the user aren't full
   * stored
   * into the data source of Silverpeas.
   * @throws AuthenticationException if the authentication fails (the pair identifier/password
   * isn't
   * correct).
   */
  @Override
  public Principal authenticate(final Credentials credentials) throws AuthenticationException {
    Principal principal = null;
    if (credentials instanceof SimpleCredentials) {
      principal = authenticate((SimpleCredentials) credentials);
    } else if (credentials instanceof TokenCredentials) {
      principal = authenticate((TokenCredentials) credentials);
    }
    return principal;
  }

  private Principal authenticate(SimpleCredentials credentials) throws AuthenticationException {
    Principal principal = null;
    String[] userIdParts = fetchUserIdParts(credentials.getUserID());
    if (userIdParts != null && userIdParts.length == 2) {
      String login = userIdParts[0];
      String domainId = userIdParts[1];
      SilverpeasUser user = getSilverpeasUser(login, domainId);
      if (user != null) {
        if (!user.mustBeAuthenticated()) {
          PasswordEncryption encryption = PasswordEncryptionFactory.getFactory()
              .getPasswordEncryption(user.getEncryptedPassword());
          try {
            encryption.check(new String(credentials.getPassword()), user.getEncryptedPassword());
          } catch (AssertionError error) {
            throw new AuthenticationException(error.getMessage());
          }
        }
        principal = getSilverpeasUserPrincipal(user);
      }
    }
    return principal;
  }

  private Principal authenticate(TokenCredentials credentials) throws AuthenticationException {
    Principal principal = null;
    String token = credentials.getToken();
    String userID = credentials.getAttribute(USERID_TOKEN_ATTRIBUTE);
    if (matches(token, userID)) {
      String[] userIdParts = fetchUserIdParts(userID);
      if (userIdParts != null && userIdParts.length == 2) {
        String login = userIdParts[0];
        String domainId = userIdParts[1];
        SilverpeasUser user = getSilverpeasUser(login, domainId);
        if (user != null) {
          principal = getSilverpeasUserPrincipal(user);
        } else {
          // a TokenCredentials must match an existing user. Otherwise, it is considered as a
          // forbidden access
          throw new AuthenticationException("No session matching an existing user in Silverpeas");
        }
      }
    } else {
      throw new AuthenticationException("Invalid authentication token");
    }
    return principal;
  }

  private SilverpeasUser getSilverpeasUser(final String login, final String domainId) {
    SilverpeasUser user = SilverpeasUser.asJcrSystemUser();
    if (!user.getLogin().equals(login) || !user.getDomainId().equals(domainId)) {
      user = null;
      try (Connection connection = openConnectionToDataSource();
           PreparedStatement domainStatement = connection.prepareStatement(SELECT_DOMAIN_TABLE)) {
        domainStatement.setInt(1, Integer.parseInt(domainId));
        try (ResultSet domainResultSet = domainStatement.executeQuery()) {
          if (domainResultSet.next()) {
            String className = domainResultSet.getString("classname");
            if (className != null && className.toLowerCase().endsWith("sqldriver")) {
              String sqlDomainTable = fetchSQLTableFrom(domainResultSet.getString("propfilename"));
              String sqlUserData = computeUserDataSQLQueryFor(sqlDomainTable);
              try (PreparedStatement userStatement = connection.prepareStatement(sqlUserData)) {
                userStatement.setString(1, login);
                try (ResultSet userResultSet = userStatement.executeQuery()) {
                  if (userResultSet.next()) {
                    user = new SilverpeasUser().withId(userResultSet.getString("id"))
                        .withDomainId(domainId).withDomainTablePrefix(sqlDomainTable)
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

  private Principal getSilverpeasUserPrincipal(final SilverpeasUser user) {
    Principal principal;
    if (user.isJcrSystemUser()) {
      principal = new SilverpeasJcrSystemPrincipal();
    } else {
      try (Connection connection = openConnectionToDataSource();
           PreparedStatement statement = connection.prepareStatement(SELECT_USER_ROLES)) {
        statement.setInt(1, Integer.parseInt(user.getId()));
        try (ResultSet resultSet = statement.executeQuery()) {
          principal = new SilverpeasUserPrincipal(user.getId(), "A".equals(user.getAccessLevel()));
          while (resultSet.next()) {
            String componentInstanceId = resultSet.getString("instanceid");
            String componentName = resultSet.getString("componentname");
            String roleName = resultSet.getString("rolename");
            SilverpeasUserProfile profile =
                new SilverpeasUserProfile(componentName + componentInstanceId, roleName);
            ((SilverpeasUserPrincipal) principal).addUserProfile(profile);
          }
        }
      } catch (SQLException e) {
        principal = null;
        Logger.getLogger(getClass().getSimpleName()).log(Level.SEVERE, e.getMessage(), e);
      }
    }
    return principal;
  }

  private String[] fetchUserIdParts(String userId) {
    return userId.split("@domain");
  }

  private String fetchSQLTableFrom(String propFileName) {
    int lastSepIndex = propFileName.lastIndexOf(".");
    return (lastSepIndex > 0 ? propFileName.substring(lastSepIndex + 1).toLowerCase() : null);
  }

  private String computeUserDataSQLQueryFor(String tableName) {
    return MessageFormat.format(SELECT_USER_DATA, tableName);
  }

  private Connection openConnectionToDataSource() throws SQLException {
    try {
      DataSource dataSource = InitialContext.doLookup("java:/datasources/silverpeas");
      return dataSource.getConnection();
    } catch (NamingException e) {
      throw new SQLException(e);
    }
  }

  private static boolean isDefined(String value) {
    return value != null && !value.trim().isEmpty();
  }

  private static boolean matches(String token, String userID) {
    return isDefined(token) && isDefined(userID);
  }
}
