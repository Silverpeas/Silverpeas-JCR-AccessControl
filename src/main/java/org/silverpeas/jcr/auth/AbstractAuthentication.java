/**
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

import org.silverpeas.jcr.jaas.SilverpeasJcrSystemPrincipal;
import org.silverpeas.jcr.jaas.SilverpeasUserPrincipal;
import org.silverpeas.jcr.jaas.SilverpeasUserProfile;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import java.security.Principal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class defines common operations authentication mechanisms can require in order to perform
 * their authentication.
 * @author mmoquillon
 */
public abstract class AbstractAuthentication implements Authentication {

  private static final String SELECT_USER_ROLES =
      "select r.rolename, r.instanceid, c.componentname from st_userrole_user_rel u join " +
          "st_userrole r on u.userroleid = r.id join st_componentinstance c on " +
          "c.id = r.instanceid where u.userid = ?";

  protected Principal getSilverpeasUserPrincipal(final SilverpeasUser user) {
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

  protected String[] fetchUserIdParts(String userId) {
    return userId.split("@domain");
  }

  protected Connection openConnectionToDataSource() throws SQLException {
    try {
      DataSource dataSource = InitialContext.doLookup("java:/datasources/silverpeas");
      return dataSource.getConnection();
    } catch (NamingException e) {
      throw new SQLException(e);
    }
  }
}
