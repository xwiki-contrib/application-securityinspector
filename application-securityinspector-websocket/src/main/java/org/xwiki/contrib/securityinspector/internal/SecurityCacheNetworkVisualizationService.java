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

package org.xwiki.contrib.securityinspector.internal;

import java.util.Collection;
import java.util.HashSet;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.cache.event.CacheEntryEvent;
import org.xwiki.cache.event.CacheEntryListener;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.contrib.networkvisualization.AbstractNetworkVisualizationService;
import org.xwiki.contrib.websocket.WebSocket;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.security.SecurityReferenceFactory;
import org.xwiki.security.authorization.AuthorizationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.cache.SecurityCache;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

/**
 * WebSocket network visualization service to receive information and updates on the security cache.
 *
 * @version $Id$
 */
@Component
@Named("securitycachevisualizationservice")
@Singleton
public class SecurityCacheNetworkVisualizationService extends AbstractNetworkVisualizationService
{
    private static final String MSG_ADD = "add";
    private static final String MSG_REMOVE = "remove";
    private static final String MSG_UPDATE = "update";

    private static final String MSG_INIT = "init";

    @Inject
    private AuthorizationManager authorizationManager;

    @Inject
    private SecurityCache securityCache;

    @Inject
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    @Inject
    private SecurityReferenceFactory securityReferenceFactory;

    private final Listener listener = new Listener();

    private SecurityCacheInspector securityCacheInspector;

    private class Listener implements CacheEntryListener
    {
        @Override
        public void cacheEntryAdded(CacheEntryEvent event)
        {
            onEntryAdded(event.getEntry().getValue());
        }

        @Override
        public void cacheEntryRemoved(CacheEntryEvent event)
        {
            onEntryRemoved(event.getEntry().getValue());
        }

        @Override
        public void cacheEntryModified(CacheEntryEvent event)
        {
            onEntryModified(event.getEntry().getValue());
        }
    }

    @Override
    public void initialize() throws InitializationException
    {
        logger.debug("Initializing the SecurityCache Visualization service");
        securityCacheInspector = new SecurityCacheInspector(securityCache, entityReferenceSerializer);
        super.initialize();
    }

    @Override
    protected boolean isAllowed(DocumentReference user)
    {
        return authorizationManager.hasAccess(Right.ADMIN, user,
            new DocumentReference("xwiki", "XWiki", "XWikiPreferences"));
    }

    @Override
    protected void connect(WebSocket socket)
    {
        if (getConnectedSocketCount() == 1) {
            logger.debug("Start listening events");
            securityCacheInspector.addListener(listener);
        }

        sendNodeMessage(socket, MSG_INIT, getFullDump());
    }

    @Override
    protected String getReplyForMessage(DocumentReference sender, JSONObject json)
    {
        if (json.get(TYPE_PROPERTY).equals("refresh")) {
            return buildMessage(MSG_INIT, getFullDump()).toString();
        }
        return null;
    }

    @Override
    protected void disconnect(WebSocket socket)
    {
        if (getConnectedSocketCount() == 0) {
            logger.debug("Stop listening events");
            securityCacheInspector.removeListener(listener);
        }
    }

    private void onEntryAdded(Object entry)
    {
        onEvent(MSG_ADD, entry);
    }

    private void onEntryRemoved(Object entry)
    {
        onEvent(MSG_REMOVE, entry);
    }

    private void onEntryModified(Object entry)
    {
        onEvent(MSG_UPDATE, entry);
    }

    private void onEvent(String msg, Object entry)
    {
        onNodeEvent(msg, securityCacheInspector.getNodeJSON(entry));
    }

    private JSONArray getFullDump()
    {
        JSONArray nodes = new JSONArray();
        dumpEntries(securityCacheInspector.getEntry(securityReferenceFactory.newEntityReference(null)), nodes);

        return nodes;
    }

    private void dumpEntries(Object entry, JSONArray nodes) {
        dumpEntries(entry, nodes, new HashSet<String>());
    }

    private void dumpEntries(Object entry, JSONArray nodes, Collection<String> visitedKeys) {
        if (visitedKeys.add(securityCacheInspector.getKey(entry))) {
            nodes.add(securityCacheInspector.getNodeJSON(entry));
            if (securityCacheInspector.getParents(entry) != null) {
                for (Object parent : securityCacheInspector.getParents(entry).toArray()) {
                    dumpEntries(parent, nodes, visitedKeys);
                }
            }
            if (securityCacheInspector.getChildren(entry) != null) {
                for (Object child : securityCacheInspector.getChildren(entry).toArray()) {
                    dumpEntries(child, nodes, visitedKeys);
                }
            }
        }
    }
}
