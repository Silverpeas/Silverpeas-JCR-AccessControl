package org.silverpeas.jcr.auth;

/**
 * Exception thrown when the authentication failed.
 * @author mmoquillon
 */
public class AuthenticationException extends Exception {

  public AuthenticationException() {
    super();
  }

  public AuthenticationException(final String message) {
    super(message);
  }

  public AuthenticationException(final String message, final Throwable cause) {
    super(message, cause);
  }

  public AuthenticationException(final Throwable cause) {
    super(cause);
  }

  protected AuthenticationException(final String message, final Throwable cause,
      final boolean enableSuppression, final boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
