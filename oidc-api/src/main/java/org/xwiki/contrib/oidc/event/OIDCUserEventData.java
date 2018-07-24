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
package org.xwiki.contrib.oidc.event;

/**
 * Data sent with user related events.
 *
 * @version $Id$
 * @since 1.4
 */
public class OIDCUserEventData {
//    private final OIDCIdToken idToken;
//
//    private final OIDCUserInfo userInfo;

    private final OAuthUserInfo userInfo;

    /**
     * @param// idToken the id token
     * @param// userInfo the user info
     */
//    public OIDCUserEventData(OIDCIdToken idToken, OIDCUserInfo userInfo)
//    {
//        this.idToken = idToken;
//        this.userInfo = userInfo;
//    }
    public OIDCUserEventData(OAuthUserInfo userInfo) {
        this.userInfo = userInfo;
    }

    public OAuthUserInfo getUserInfo() {
        return userInfo;
    }

    /**
     * @return the id token
     */
//    public OIDCIdToken getIdToken()
//    {
//        return this.idToken;
//    }

    /**
     * @return the user info
     */
//    public OIDCUserInfo getUserInfo()
//    {
//        return this.userInfo;
//    }
}
