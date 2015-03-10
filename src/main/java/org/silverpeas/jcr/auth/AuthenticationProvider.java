package org.silverpeas.jcr.auth;

/**
 * A provider authentication mechanisms, each of them implementing the
 * {@code org.silverpeas.jcr.auth.Authentication} interface.
 * @author mmoquillon
 */
public class AuthenticationProvider {

  private static Authentication[] authentications =
      new Authentication[]{
          new SQLSimpleAuthentication(),
          new TokenAuthentication()};

  /**
   * Gets all the authentication mechanisms supported by the access controller.
   * @return an array of Authentication objects.
   */
  public static Authentication[] getAuthentications() {
    return authentications;
  }
}
