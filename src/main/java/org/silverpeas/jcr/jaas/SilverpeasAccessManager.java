/**
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

package org.silverpeas.jcr.jaas;

import org.apache.jackrabbit.core.HierarchyManager;
import org.apache.jackrabbit.core.id.ItemId;
import org.apache.jackrabbit.core.security.AMContext;
import org.apache.jackrabbit.core.security.AccessManager;
import org.apache.jackrabbit.core.security.authorization.AccessControlProvider;
import org.apache.jackrabbit.core.security.authorization.Permission;
import org.apache.jackrabbit.core.security.authorization.WorkspaceAccessManager;
import org.apache.jackrabbit.spi.Name;
import org.apache.jackrabbit.spi.Path;
import org.apache.jackrabbit.spi.commons.conversion.NamePathResolver;

import javax.jcr.AccessDeniedException;
import javax.jcr.ItemNotFoundException;
import javax.jcr.NamespaceException;
import javax.jcr.Node;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.nodetype.NodeType;
import javax.security.auth.Subject;
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

  private HierarchyManager manager;
  private NamePathResolver resolver;
  private WorkspaceAccessManager wspAccessMgr;
  private Subject subject;
  private boolean initialized;
  private boolean isSystemPrivilege;
  private Session session;

  @Override
  public boolean canAccess(String workspaceName) throws RepositoryException {
    if (isSystemPrivilege || wspAccessMgr == null) {
      return true;
    }
    return wspAccessMgr.grants(subject.getPrincipals(), workspaceName);
  }

  @Override
  public void checkPermission(ItemId id, int permissions) throws RepositoryException {
    if (!initialized) {
      throw new IllegalStateException("not initialized");
    }
    if (!isGranted(id, permissions)) {
      throw new AccessDeniedException();
    }
  }

  @Override
  public synchronized void close() throws Exception {
    if (!initialized) {
      throw new IllegalStateException("not initialized");
    }
    initialized = false;
  }

  @Override
  public void init(AMContext context) throws Exception {
    if (initialized) {
      throw new IllegalStateException("already initialized");
    }
    this.manager = context.getHierarchyManager();
    this.resolver = context.getNamePathResolver();
    this.subject = context.getSubject();
    this.session = context.getSession();
    this.isSystemPrivilege = !subject.getPrincipals(SilverpeasJcrSystemPrincipal.class).isEmpty();
    this.initialized = true;
  }

  @Override
  public boolean isGranted(ItemId id, int permissions) throws RepositoryException {
    if (!initialized) {
      throw new IllegalStateException("not initialized");
    }
    if (id.denotesNode() && !isSystemPrivilege) {
      Path path = manager.getPath(id);
      if (path.getDepth() > 2 && validateNode(path)) {
        return isPathAutorized(path);
      } else if (validateFileNode(id)) {
        Set<SilverpeasUserPrincipal> principals =
            subject.getPrincipals(SilverpeasUserPrincipal.class);
        for (SilverpeasUserPrincipal principal : principals) {
          if (principal.isAdministrator() || checkUserIsOwner(principal, id)) {
            return true;
          }
        }
        return false;
      }
    }
    return true;
  }

  /**
   * In the case the node has a property of belonging, checks it is then owned by the specified
   * user.
   * A node has a such property when the resource behind the node was locked by the user.
   * @param principal the principal of the user.
   * @param id the unique identifier of the JCR item.
   * @return true if the user owns the item or the item doesn't exist or it has no property of
   * belonging. False otherwise.
   * @throws RepositoryException if an error occurs while access the JCR repository.
   */
  protected boolean checkUserIsOwner(SilverpeasUserPrincipal principal, ItemId id)
      throws RepositoryException {
    try {
      Node node = getNode(session, id);
      if (node.hasProperty(SLV_PROPERTY_OWNER)) {
        return principal.getUserId().equals(node.getProperty(SLV_PROPERTY_OWNER).getString());
      }
      return true;
    } catch (ItemNotFoundException ex) {
      // The node doesn't exist so we may assume that it is transient in the user's session
      return true;
    }
  }

  /**
   * Checks the node at the given path is owned by the specified user.
   * A node has a such property when the resource behind the node was locked by the user.
   * @param principal the principal of the user.
   * @param path the path of the node in the JCR repository.
   * @return true if the user owns the node or there is no such node. False otherwise.
   * @throws RepositoryException if an error occurs while access the JCR repository.
   */
  protected boolean checkUserIsOwner(SilverpeasUserPrincipal principal, Path path)
      throws RepositoryException {
    try {
      Node node = getNode(session, path);
      return principal.getUserId().equals(node.getProperty(SLV_PROPERTY_OWNER).getString());
    } catch (ItemNotFoundException ex) {
      // The node doesn't exist so we may assume that it is transient in the user's session
      return true;
    }
  }

  protected boolean isPathAutorized(Path path) {
    Set<SilverpeasUserPrincipal> principals = subject.getPrincipals(SilverpeasUserPrincipal.class);
    Path.Element[] elements = path.getElements();
    for (SilverpeasUserPrincipal principal : principals) {
      for (Path.Element element : elements) {
        if (principal.isAdministrator() ||
            principal.getUserProfile(element.getName().getLocalName()) != null) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * A way to block the webdav access to a file.
   * In the case of a webdav access, checks the specified node has a property of belonging.
   * @param id the unique identifier of the JCR item.
   * @return true if the node matches a file and it has a property of belonging. False otherwise.
   * @throws RepositoryException if an error occurs while accessing the JCR repository.
   */
  protected boolean validateFileNode(ItemId id) throws RepositoryException {
    Node node = getNode(session, id);
    return validateFileNode(node);
  }

  protected boolean validateNode(Path path) throws RepositoryException {
    Node node = getNode(session, path);
    return validateNode(node);
  }

  protected boolean validateNode(Node node) throws RepositoryException {
    return node.getPrimaryNodeType().isNodeType(NT_FOLDER);
  }

  /**
   * A way to block the webdav access to a file.
   * In the case of a webdav access, checks the specified node has a property of belonging.
   * @param path the path of a node in the JCR repository.
   * @return true if the node matches a file and it has a property of belonging. False otherwise.
   * @throws RepositoryException if an error occurs while accessing the JCR repository.
   */
  protected boolean validateFileNode(Path path) throws RepositoryException {
    try {
      Node node = getNode(session, path);
      return validateFileNode(node);
    } catch (RepositoryException rex) {
      return false;
    }
  }

  protected boolean validateFileNode(Node node) throws RepositoryException {
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

  @Override
  public void init(AMContext context, AccessControlProvider acProvider,
      WorkspaceAccessManager wspAccessManager) throws Exception {
    if (initialized) {
      throw new IllegalStateException("already initialized");
    }
    this.manager = context.getHierarchyManager();
    this.resolver = context.getNamePathResolver();
    this.wspAccessMgr = wspAccessManager;
    this.subject = context.getSubject();
    this.isSystemPrivilege = !subject.getPrincipals(SilverpeasJcrSystemPrincipal.class).isEmpty();
    this.session = context.getSession();
    this.initialized = true;
  }

  @Override
  public void checkPermission(Path absPath, int permissions) throws RepositoryException {
    if (!isGranted(absPath, permissions)) {
      throw new AccessDeniedException("Access denied");
    }
  }

  @Override
  public boolean isGranted(Path path, int permissions) throws RepositoryException {
    if (!isSystemPrivilege && denotesNode(path)) {
      if (path.getDepth() > 2 && validateNode(path)) {
        return isPathAutorized(path);
      } else if (validateFileNode(path)) {
        Set<SilverpeasUserPrincipal> principals =
            subject.getPrincipals(SilverpeasUserPrincipal.class);
        for (SilverpeasUserPrincipal principal : principals) {
          if (principal.isAdministrator() || checkUserIsOwner(principal, path)) {
            return true;
          }
        }
        return false;
      }
    }
    return true;

  }

  protected boolean denotesNode(Path path) throws NamespaceException {
    String relativePath = getRelativePath(path);
    try {
      Node root = session.getRootNode();
      if (path.denotesRoot()) {
        return true;
      }
      if (root.hasNode(relativePath)) {
        return true;
      }
      return false;
    } catch (RepositoryException ex) {
      return false;
    }
  }

  protected Node getNode(Session session, Path path) throws RepositoryException {
    String relativePath = getRelativePath(path);
    Node root = session.getRootNode();
    if (path.denotesRoot()) {
      return root;
    }
    if (root.hasNode(relativePath)) {
      return root.getNode(relativePath);
    }
    return null;

  }

  protected Node getNode(Session session, ItemId id) throws RepositoryException {
    return session.getNodeByIdentifier(id.toString());
  }

  protected String getRelativePath(Path path) throws NamespaceException {
    String result = this.resolver.getJCRPath(path);
    if (result.startsWith("/")) {
      result = result.substring(1);
    }
    return result;
  }

  @Override
  public boolean isGranted(Path path, Name name, int permission) throws RepositoryException {
    boolean canAccessPath = true;
    if (path != null) {
      canAccessPath = isGranted(path, permission);
    }
    return canAccessPath;
  }

  @Override
  public boolean canRead(Path path, ItemId itemid) throws RepositoryException {
    boolean canAccessPath = true;
    if (path != null) {
      canAccessPath = isGranted(path, Permission.READ);
    }
    return canAccessPath && isGranted(itemid, Permission.READ);
  }

  @Override
  public void checkRepositoryPermission(int permissions) throws RepositoryException {
  }

}
