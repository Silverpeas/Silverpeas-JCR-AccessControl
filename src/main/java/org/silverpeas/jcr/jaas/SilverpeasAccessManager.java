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

import org.apache.jackrabbit.core.id.ItemId;
import org.apache.jackrabbit.core.id.NodeId;
import org.apache.jackrabbit.core.id.PropertyId;
import org.apache.jackrabbit.core.security.AMContext;
import org.apache.jackrabbit.core.security.AccessManager;
import org.apache.jackrabbit.core.security.AnonymousPrincipal;
import org.apache.jackrabbit.core.security.SystemPrincipal;
import org.apache.jackrabbit.core.security.UserPrincipal;
import org.apache.jackrabbit.core.security.authorization.AccessControlProvider;
import org.apache.jackrabbit.core.security.authorization.Permission;
import org.apache.jackrabbit.core.security.authorization.WorkspaceAccessManager;
import org.apache.jackrabbit.spi.Name;
import org.apache.jackrabbit.spi.Path;
import org.apache.jackrabbit.spi.commons.name.PathFactoryImpl;
import org.silverpeas.jcr.auth.SilverpeasUser;

import javax.jcr.AccessDeniedException;
import javax.jcr.ItemNotFoundException;
import javax.jcr.Node;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.jcr.nodetype.NodeType;
import javax.security.auth.Subject;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.silverpeas.jcr.JcrProperties.*;

/**
 * The access manager controls the access rights of a Silverpeas user to access some resources
 * in the JCR repository.
 * <p/>
 * By default, an authenticated user has access the whole content of the JCR repository. The only
 * restriction is when a node has property of belonging, its access is authorized to only the owner
 * of the node.
 */
public class SilverpeasAccessManager implements AccessManager {

  /**
   * The name of the JCR workspace used by Silverpeas to store some of its data.
   */
  private static final String SILVERPEAS_WORKSPACE = "silverpeas";

  private static final String WORKSPACE_ACCESS_DENIED =
      "The user doesn't have the right to access the workspace {0}";

  private static final List<String> WRITING_ROLES = Arrays.asList("admin", "publisher", "writer");

  private AMContext context = null;
  private WorkspaceAccessManager wspAccessMgr;
  private byte accessMap = 0;
  private NodeId rootNodeId;
  boolean initialized = false;

  /**
   * Initialize this access manager. An <code>AccessDeniedException</code> will
   * be thrown if the subject of the given <code>context</code> is not
   * granted access to the specified workspace.
   * @param context access manager context
   * @throws javax.jcr.AccessDeniedException if the subject is not granted access
   * to the specified workspace.
   * @throws Exception if another error occurs
   */
  @Override
  public void init(final AMContext context) throws AccessDeniedException, Exception {
    init(context, null, null);
  }

  /**
   * Initialize this access manager. An <code>AccessDeniedException</code> will
   * be thrown if the subject of the given <code>context</code> is not
   * granted access to the specified workspace.
   * @param context access manager context.
   * @param acProvider The access control provider.
   * @param wspAccessMgr The workspace access manager.
   * @throws javax.jcr.AccessDeniedException if the subject is not granted access
   * to the specified workspace.
   * @throws Exception if another error occurs
   */
  @Override
  public void init(final AMContext context, final AccessControlProvider acProvider,
      final WorkspaceAccessManager wspAccessMgr) throws AccessDeniedException, Exception {
    mustNotBeYetInitialized();
    this.context = context;
    this.rootNodeId =
        context.getHierarchyManager().resolveNodePath(PathFactoryImpl.getInstance().getRootPath());
    this.wspAccessMgr = wspAccessMgr;
    initAccessMap(context.getSubject());
    if (!canAccess(context.getWorkspaceName())) {
      throw new AccessDeniedException(
          MessageFormat.format(WORKSPACE_ACCESS_DENIED, context.getWorkspaceName()));
    }
    initialized = true;
  }

  /**
   * Close this access manager. After having closed an access manager,
   * further operations on this object are treated as illegal and throw
   * @throws Exception if an error occurs
   */
  @Override
  public void close() throws Exception {
    mustBeInitialized();
    context = null;
    wspAccessMgr = null;
    rootNodeId = null;
    accessMap = 0;
    initialized = false;
  }

  /**
   * Determines whether the specified <code>permissions</code> are granted
   * on the item with the specified <code>id</code> (i.e. the <i>target</i> item).
   * @param id the id of the target item
   * @param permissions A combination of one or more of the following constants
   * encoded as a bitmask value:
   * <ul>
   * <li><code>READ</code></li>
   * <li><code>WRITE</code></li>
   * <li><code>REMOVE</code></li>
   * </ul>
   * @throws javax.jcr.AccessDeniedException if permission is denied
   * @throws javax.jcr.ItemNotFoundException if the target item does not exist
   * @throws javax.jcr.RepositoryException it an error occurs
   * @deprecated
   */
  @Override
  @Deprecated
  public void checkPermission(final ItemId id, final int permissions)
      throws AccessDeniedException, ItemNotFoundException, RepositoryException {
    if (!isGranted(id, permissions)) {
      throw new AccessDeniedException();
    }
  }

  /**
   * Determines whether the specified <code>permissions</code> are granted
   * on the item with the specified <code>id</code> (i.e. the <i>target</i> item).
   * @param absPath Path to an item.
   * @param permissions A combination of one or more of the
   * {@link org.apache.jackrabbit.core.security.authorization.Permission}
   * constants encoded as a bitmask value.
   * @throws javax.jcr.AccessDeniedException if permission is denied
   * @throws javax.jcr.RepositoryException it another error occurs
   */
  @Override
  public void checkPermission(final Path absPath, final int permissions)
      throws AccessDeniedException, RepositoryException {
    if (!isGranted(absPath, permissions)) {
      throw new AccessDeniedException();
    }
  }

  /**
   * Determines whether the specified <code>permissions</code> are granted
   * on the repository level.
   * @param permissions The permissions to check.
   * @throws javax.jcr.AccessDeniedException if permissions are denied.
   * @throws javax.jcr.RepositoryException if another error occurs.
   */
  @Override
  public void checkRepositoryPermission(final int permissions)
      throws AccessDeniedException, RepositoryException {

  }

  /**
   * Determines whether the specified <code>permissions</code> are granted
   * on the item with the specified <code>id</code> (i.e. the <i>target</i> item).
   * @param id the id of the target item
   * @param permissions A combination of one or more of the following constants
   * encoded as a bitmask value:
   * <ul>
   * <li><code>READ</code></li>
   * <li><code>WRITE</code></li>
   * <li><code>REMOVE</code></li>
   * </ul>
   * @return <code>true</code> if permission is granted; otherwise <code>false</code>
   * @throws javax.jcr.ItemNotFoundException if the target item does not exist
   * @throws javax.jcr.RepositoryException if another error occurs
   * @deprecated
   */
  @Deprecated
  @Override
  public boolean isGranted(final ItemId id, final int permissions)
      throws ItemNotFoundException, RepositoryException {
    mustBeInitialized();
    if (isSystemAccess()) {
      return true;
    }
    Path path = context.getHierarchyManager().getPath(id);
    return isGranted(path, permissions);
  }

  /**
   * Determines whether the specified <code>permissions</code> are granted
   * on the item with the specified <code>absPath</code> (i.e. the <i>target</i>
   * item, that may or may not yet exist).
   * @param absPath the absolute path to test
   * @param permissions A combination of one or more of the
   * {@link org.apache.jackrabbit.core.security.authorization.Permission}
   * constants encoded as a bitmask value.
   * @return <code>true</code> if the specified permissions are granted;
   * otherwise <code>false</code>.
   * @throws javax.jcr.RepositoryException if an error occurs.
   */
  @Override
  public boolean isGranted(final Path absPath, final int permissions) throws RepositoryException {
    if (!absPath.isAbsolute()) {
      throw new RepositoryException("Absolute path expected");
    }
    if (isSystemAccess()) {
      return true;
    }

    boolean isGranted = false;
    if (denotesNode(absPath)) {
      Session session = openSystemSession();
      try {
        String jcrPath = context.getNamePathResolver().getJCRPath(absPath);
        Node node = session.getNode(jcrPath);
        if (isFolder(node)) {
          // only those with the correct roles can access it (for reading or modifying it).
          isGranted = isPathAuthorized(absPath, permissions);
        } else if (isLockedFile(node)) {
          // only the user owning the file can access it (for reading or updating it).
          isGranted = isFileAuthorized(node);
        } else {
          // it is an ordinary JCR node: everyone can read it but only those with specific roles
          // can update it.
          isGranted = permissions == Permission.READ || isPathAuthorized(absPath, permissions);
        }
      } finally {
        session.logout();
      }
    } else if (denotesProperty(absPath)) {
      // it is a property, checks the right of the user to access its holder.
      isGranted = isGranted(absPath.getAncestor(1), permissions);
    }
    return isGranted;
  }

  /**
   * Determines whether the specified <code>permissions</code> are granted
   * on an item represented by the combination of the given
   * <code>parentPath</code> and <code>childName</code> (i.e. the <i>target</i>
   * item, that may or may not yet exist).
   * @param parentPath Path to an existing parent node.
   * @param childName Name of the child item that may or may not exist yet.
   * @param permissions A combination of one or more of the
   * {@link org.apache.jackrabbit.core.security.authorization.Permission}
   * constants encoded as a bitmask value.
   * @return <code>true</code> if the specified permissions are granted;
   * otherwise <code>false</code>.
   * @throws javax.jcr.RepositoryException if an error occurs.
   */
  @Override
  public boolean isGranted(final Path parentPath, final Name childName, final int permissions)
      throws RepositoryException {
    Path path = PathFactoryImpl.getInstance().create(parentPath, childName, true);
    return isGranted(path, permissions);
  }

  /**
   * Determines whether the item with the specified <code>itemPath</code>
   * or <code>itemId</code> can be read. Either of the two parameters
   * may be <code>null</code>.<br>
   * Note, that this method should only be called for persisted items as NEW
   * items may not be visible to the permission evaluation.
   * For new items {@link #isGranted(org.apache.jackrabbit.spi.Path, int)} should be used
   * instead.<p/>
   * If this method is called with both Path and ItemId it is left to the
   * evaluation, which parameter is used.
   * @param itemPath The path to the item or <code>null</code> if itemId
   * should be used to determine the READ permission.
   * @param itemId Id of the item to be tested or <code>null</code> if the
   * itemPath should be used to determine the permission.
   * @return <code>true</code> if the item can be read; otherwise <code>false</code>.
   * @throws javax.jcr.RepositoryException if the item is NEW and only an itemId is
   * specified or if another error occurs.
   */
  @Override
  public boolean canRead(final Path itemPath, final ItemId itemId) throws RepositoryException {
    mustBeInitialized();
    if (isSystemAccess()) {
      return true;
    }

    Path path = itemPath;
    if (path == null) {
      path = context.getHierarchyManager().getPath(itemId);
    }
    return isGranted(path, Permission.READ);
  }

  /**
   * Determines whether the subject of the current context is granted access
   * to the given workspace. Note that an implementation is free to test for
   * the existence of a workspace with the specified name. In this case
   * the expected return value is <code>false</code>, if no such workspace
   * exists.
   * @param workspaceName name of workspace
   * @return <code>true</code> if the subject of the current context is
   * granted access to the given workspace; otherwise <code>false</code>.
   * @throws javax.jcr.RepositoryException if an error occurs.
   */
  @Override
  public boolean canAccess(final String workspaceName) throws RepositoryException {
    if (SILVERPEAS_WORKSPACE.equals(workspaceName)) {
      return isSilverpeasUserAccess() || isSystemAccess();
    } else if (wspAccessMgr != null) {
      return wspAccessMgr.grants(context.getSubject().getPrincipals(), workspaceName);
    }
    return true;
  }

  private boolean isPathAuthorized(Path path, int permissions) {
    Set<SilverpeasUserPrincipal> principals =
        context.getSubject().getPrincipals(SilverpeasUserPrincipal.class);
    Path.Element[] elements = path.getElements();
    for (SilverpeasUserPrincipal principal : principals) {
      if (principal.isAdministrator()) {
        return true;
      }
      for (Path.Element element : elements) {
        SilverpeasUserProfile profile = principal.getUserProfile(element.getName().getLocalName());
        if (profile != null) {
          return permissions == Permission.READ || WRITING_ROLES.contains(profile.getRole());
        }
      }
    }
    return false;
  }

  private boolean isFileAuthorized(Node node) throws RepositoryException {
    Set<SilverpeasUserPrincipal> principals =
        context.getSubject().getPrincipals(SilverpeasUserPrincipal.class);
    for (SilverpeasUserPrincipal principal : principals) {
      if (principal.isAdministrator() || isUserOwnsNode(principal, node)) {
        return true;
      }
    }
    return false;
  }

  private void initAccessMap(final Subject subject) {
    accessMap |= (subject.getPrincipals(SystemPrincipal.class).isEmpty() &&
        subject.getPrincipals(SilverpeasJcrSystemPrincipal.class).isEmpty() ? 0 : 1);
    accessMap |= (subject.getPrincipals(SilverpeasUserPrincipal.class).isEmpty() ? 0 : 2);
    accessMap |= (subject.getPrincipals(UserPrincipal.class).isEmpty() ? 0 : 4);
    accessMap |= (subject.getPrincipals(AnonymousPrincipal.class).isEmpty() ? 0 : 8);
  }

  private boolean isSystemAccess() {
    return (accessMap & 1) == 1;
  }

  private boolean isSilverpeasUserAccess() {
    return (accessMap & 2) == 2;
  }

  private boolean isUserAccess() {
    return (accessMap & 4) == 4;
  }

  private boolean isAnonymousAccess() {
    return (accessMap & 8) == 8;
  }

  private boolean isFolder(Node node) throws RepositoryException {
    return node.getPrimaryNodeType().isNodeType(NT_FOLDER);
  }

  private boolean isLockedFile(Node node) throws RepositoryException {
    if (NT_FILE.equals(node.getPrimaryNodeType().getName())) {
      NodeType[] mixins = node.getMixinNodeTypes();
      for (NodeType mixin : mixins) {
        if (SLV_OWNABLE_MIXIN.equals(mixin.getName())) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Checks the specified user owns the specified locked file.
   * @param principal the principal of the user in Silverpeas.
   * @param node the node representing a locked file.
   * @return true if the user owns the item or the item doesn't exist or it has no property of
   * belonging. False otherwise.
   * @throws RepositoryException if an error occurs while access the JCR repository.
   */
  private boolean isUserOwnsNode(SilverpeasUserPrincipal principal, Node node)
      throws RepositoryException {
    try {
      if (node.hasProperty(SLV_PROPERTY_OWNER)) {
        return principal.getUserId().equals(node.getProperty(SLV_PROPERTY_OWNER).getString());
      }
      return true;
    } catch (ItemNotFoundException ex) {
      // The node doesn't exist so we may assume that it is transient in the user's session
      return true;
    }
  }

  private void mustBeInitialized() {
    if (!initialized) {
      throw new IllegalStateException("The access manager isn't initialized!");
    }
  }

  private void mustNotBeYetInitialized() {
    if (initialized) {
      throw new IllegalStateException("The access manager is already initialized!");
    }
  }

  private boolean denotesNode(Path path) {
    try {
      if (path.denotesRoot()) {
        return true;
      }
      NodeId nodeId = context.getHierarchyManager().resolveNodePath(path);
      return nodeId != null && nodeId.denotesNode();
    } catch (RepositoryException ex) {
      return false;
    }
  }

  private boolean denotesProperty(Path path) {
    try {
      if (path.denotesRoot()) {
        return false;
      }
      PropertyId propertyId = context.getHierarchyManager().resolvePropertyPath(path);
      return propertyId != null && !propertyId.denotesNode();

    } catch (RepositoryException ex) {
      return false;
    }
  }

  private Session openSystemSession() throws RepositoryException {
    SilverpeasUser system = SilverpeasUser.asJcrSystemUser();
    String systemLogin = system.getLogin() + "@domain" + system.getDomainId();
    return context.getSession()
        .getRepository()
        .login(new SimpleCredentials(systemLogin, new char[0]));
  }
}
