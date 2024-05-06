/**
 * This file is part of lavagna.
 *
 * lavagna is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * lavagna is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with lavagna.  If not, see <http://www.gnu.org/licenses/>.
 */
package io.lavagna.web.security.login.oauth;

import org.scribe.builder.api.DefaultApi20;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.*;
import org.scribe.oauth.OAuth20ServiceImpl;
import org.scribe.oauth.OAuthService;

import static io.lavagna.web.security.login.oauth.Utils.encode;

class Discord20Api extends DefaultApi20 {

	@Override
	public String getAccessTokenEndpoint() {
		return "https://discord.com/api/oauth2/token";
	}

	@Override
	public String getAuthorizationUrl(OAuthConfig config) {
		return "https://discord.com/oauth2/authorize?client_id=" + encode(config.getApiKey()) + "&redirect_uri="
				+ encode(config.getCallback()) + "&response_type=code&scope=identify+email+openid";
	}

    public Verb getAccessTokenVerb() {
        return Verb.POST;
    }

    public AccessTokenExtractor getAccessTokenExtractor() {
        return new JsonTokenExtractor();
    }

    @Override
    public OAuthService createService(OAuthConfig config) {
        return new OAuth20ServiceImpl(this, config) {
            @Override
            public Token getAccessToken(Token requestToken, Verifier verifier) {
                OAuthRequest request = new OAuthRequest(getAccessTokenVerb(), getAccessTokenEndpoint());
                request.addBodyParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
                request.addBodyParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
                request.addBodyParameter(OAuthConstants.CODE, verifier.getValue());
                request.addBodyParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
                request.addBodyParameter("grant_type", "authorization_code");
                request.addBodyParameter(OAuthConstants.SCOPE, "identify email openid");
                request.addHeader("User-Agent", "Mozilla/5.0 (compatible; Lavagna/1.0; +https://lavagna.io)");

                Response response = request.send();
                String body = response.getBody();
                return getAccessTokenExtractor().extract(response.getBody());
            }

            @Override
            public void signRequest(Token accessToken, OAuthRequest request) {
                request.addHeader("Authorization", "Bearer " + accessToken.getToken());
            }
        };
    }
}
