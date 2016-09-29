/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.xwiki.contrib.securityinspector.internal

import net.sf.json.JSONObject
import org.xwiki.cache.event.CacheEntryListener
import org.xwiki.model.EntityType
import org.xwiki.model.reference.EntityReferenceSerializer
import org.xwiki.security.GroupSecurityReference
import org.xwiki.security.SecurityReference
import org.xwiki.security.authorization.SecurityAccessEntry
import org.xwiki.security.authorization.SecurityRuleEntry
import org.xwiki.security.authorization.cache.SecurityCache
import org.xwiki.security.authorization.cache.SecurityShadowEntry
/**
 * A groovy helper to inspect private information from the security cache.
 *
 * @version $Id$
 */
public class SecurityCacheInspector
{
    def cache, serializer;

    public SecurityCacheInspector(SecurityCache cache, EntityReferenceSerializer<String> serializer)
    {
        this.cache = cache;
        this.serializer = serializer;
    }

    public def getEntry(SecurityReference reference)
    {
        return this.cache.getEntry(reference);
    }

    public String getKey(def cacheEntry) {
        return cacheEntry.key;
    }

    public Collection<?> getParents(def cacheEntry) {
        return cacheEntry.parents;
    }

    public Collection<?> getChildren(def cacheEntry) {
        return cacheEntry.children;
    }

    public JSONObject getNodeJSON(def cacheEntry)
    {
        if (cacheEntry == null) return null;

        JSONObject node = new JSONObject();
        def entry = cacheEntry.getEntry();
        def originalEntry = entry instanceof SecurityShadowEntry ? this.cache.getEntry(entry.reference) : null;

        node.put('key', cacheEntry.key);
        node.put('isUser', cacheEntry.isUser());
        node.put('disposed', cacheEntry.disposed);
        node.put('reference', serializer.serialize(entry.reference));
        if (entry instanceof SecurityAccessEntry) {
            node.put('userReference', serializer.serialize(entry.userReference));
        }
        node.put('type',
            entry instanceof SecurityRuleEntry
                ? (entry.reference.type == EntityType.DOCUMENT
                    ? (cacheEntry.isUser()
                        ? (entry.reference instanceof GroupSecurityReference
                            ? 'group'
                            : 'user'
                          )
                        : 'doc'
                      )
                    : (entry.reference.type == EntityType.SPACE
                        ? 'space'
                        : (entry.reference.type == EntityType.WIKI
                            ? 'wiki'
                            : 'unknown'
                          )
                      )
                  )
                : (entry instanceof SecurityAccessEntry
                    ? 'access'
                    : (entry instanceof SecurityShadowEntry
                        ? 'shadow'
                        : 'unknown'
                      )
                  )
        );
        if (cacheEntry.parents) {
            node.put('parents',
                cacheEntry.parents.toArray().collect({
                    return getParentRelationJSON(cacheEntry, it, originalEntry);
                })
            );
        }
        if (cacheEntry.children) {
            node.put('children',
                cacheEntry.children.toArray().collect({
                    return getChildRelationJSON(cacheEntry, it, originalEntry);
                })
            );
        }

        return node;
    }

    private JSONObject getParentRelationJSON(def cacheEntry, def parentEntry, def originalEntry)
    {
        JSONObject parent = new JSONObject();
        parent.put('key', parentEntry.key);
        parent.put('type',
            getRelationType(cacheEntry, parentEntry, originalEntry)
        );
        return parent;
    }

    private JSONObject getChildRelationJSON(def cacheEntry, def childEntry, def originalEntry)
    {
        JSONObject parent = new JSONObject();
        parent.put('key', childEntry.key);
        parent.put('type',
            getRelationType(childEntry, cacheEntry, originalEntry)
        );
        return parent;
    }

    private String getRelationType(def child, def parent, def originalEntry)
    {
        def entry = child.getEntry();
        def pEntry = parent.getEntry();
        return entry instanceof SecurityShadowEntry && parent == originalEntry ? 'shadow'
            : (child.isUser()
                && !(entry instanceof SecurityAccessEntry)
                && pEntry.reference instanceof GroupSecurityReference
                ? 'member'
                : (entry instanceof SecurityAccessEntry
                    ? (pEntry.reference == entry.userReference
                        ? 'user'
                        : 'entity'
                      )
                    : (entry.reference.type == EntityType.DOCUMENT
                        ? 'space'
                        : (entry.reference.type == EntityType.SPACE
                            ? 'wiki'
                            : (entry.reference.type == EntityType.WIKI
                                ? 'main'
                                : 'unknown'
                              )
                          )
                      )
                  )
              )
    }

    public void addListener(CacheEntryListener listener)
    {
        this.cache.cache.addCacheEntryListener(listener);
    }

    public void removeListener(CacheEntryListener listener)
    {
        this.cache.cache.removeCacheEntryListener(listener);
    }
}
