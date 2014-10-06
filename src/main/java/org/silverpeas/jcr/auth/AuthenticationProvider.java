package org.silverpeas.jcr.auth;

/**
 * A provider of an implementation of the {@code org.silverpeas.jcr.auth.Authentication} interface.
 * @author mmoquillon
 */
public class AuthenticationProvider {

  private static Authentication authentication = new SilverpeasAuthentication();

  public static Authentication getAuthentication() {
    return authentication;
  }
}
