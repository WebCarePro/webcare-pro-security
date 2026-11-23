/**
 * WebCare Pro Security & Firewall - WordPress React 18 Reconciler Patch
 *
 * WordPress core's bundled React 18.3 is known to throw:
 * "NotFoundError: Failed to execute 'removeChild' on 'Node': The node to be removed is not a child of this node."
 * when unmounting sibling SVG and text nodes during fast stage transitions (such as navigating between wizard steps).
 *
 * This safe guard ensures unmounted or detached nodes are handled gracefully by delegating to their actual parentNode.
 */

let patchApplied = false;

export function applyDomPatch(): void {
  if (patchApplied || typeof window === 'undefined' || typeof Node === 'undefined' || !Node.prototype) {
    return;
  }

  const origRemoveChild = Node.prototype.removeChild;
  Node.prototype.removeChild = function <T extends Node>(child: T): T {
    if (child && child.parentNode !== this) {
      if (child.parentNode) {
        return child.parentNode.removeChild(child);
      }
      return child;
    }
    return origRemoveChild.call(this, child);
  };

  const origInsertBefore = Node.prototype.insertBefore;
  Node.prototype.insertBefore = function <T extends Node>(newNode: T, referenceNode: Node | null): T {
    if (referenceNode && referenceNode.parentNode !== this) {
      if (referenceNode.parentNode) {
        return referenceNode.parentNode.insertBefore(newNode, referenceNode);
      }
      return this.appendChild(newNode);
    }
    return origInsertBefore.call(this, newNode, referenceNode);
  };

  patchApplied = true;
}

// Automatically apply when module is imported in browser environments
if (typeof window !== 'undefined') {
  applyDomPatch();
}
