/**
 * Copyright (C) 2000 - 2016 Silverpeas
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
package org.silverpeas.jcr.jaas;

import org.apache.jackrabbit.core.security.authentication.CredentialsCallback;
import org.silverpeas.jcr.auth.Authentication;
import org.silverpeas.jcr.auth.AuthenticationException;
import org.silverpeas.jcr.auth.AuthenticationProvider;

import javax.jcr.Credentials;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.security.Principal;
import java.util.Map;

/**
 * A login module to authenticate the users that access the JCR repository used by Silverpeas.
 * Their access rights on the content in the JCR repository is controlled by an
 * {@code org.silverpeas.jcr.jaas.SilverpeasAccessManager} instance.
 * <p>
 * The login module delegates the authentication itself to an authentication service that has the
 * knowledge of how to perform the authentication on behalf of Silverpeas.
 */
public class SilverpeasJcrLoginModule implements LoginModule {

  private Subject subject;
  private CallbackHandler callbackHandler;
  private Credentials credentials = null;
  private Principal principal = null;


  @Override
  public boolean abort() throws LoginException {
    if (principal != null) {
      return logout();
    }
    return false;
  }

  @Override
  public boolean commit() throws LoginException {
    if (principal != null) {
      subject.getPrincipals().add(principal);
      subject.getPrivateCredentials().add(credentials);
      return true;
    }
    return false;
  }

  @Override
  public void initialize(Subject subject, CallbackHandler callbackHandler,
      Map<String, ?> sharedState, Map<String, ?> options) {
    this.subject = subject;
    this.callbackHandler = callbackHandler;
  }

  @Override
  public boolean login() throws LoginException {
    // prompt for a user name and password
    if (callbackHandler == null) {
      throw new LoginException("no callback handler available");
    }
    try {
      // Get credentials using a JAAS callback
      CredentialsCallback credentialsCallback = new CredentialsCallback();
      callbackHandler.handle(new Callback[]{credentialsCallback});
      Credentials credentials = credentialsCallback.getCredentials();
      // Use the credentials to authenticate the subject and then to get its principal to access
      // the JCR repository
      principal = null;
      if (credentials != null) {
        Authentication[] authentications = AuthenticationProvider.getAuthentications();
        for (int i = 0; i < authentications.length && principal == null; i++) {
          principal = authentications[i].authenticate(credentials);
        }
      }
    } catch (IOException | AuthenticationException ex) {
      throw new LoginException(ex.getMessage());
    } catch (UnsupportedCallbackException e) {
      throw new LoginException(e.getCallback().toString() + " not available");
    }
    return principal != null;
  }

  @Override
  public boolean logout() throws LoginException {
    subject.getPrincipals().remove(principal);
    return true;
  }
}
