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

import com.google.gson.*;
import com.google.gson.annotations.SerializedName;
import io.lavagna.web.security.Redirector;
import io.lavagna.web.security.SecurityConfiguration;
import io.lavagna.web.security.SecurityConfiguration.SessionHandler;
import io.lavagna.web.security.SecurityConfiguration.Users;
import io.lavagna.web.security.login.oauth.OAuthResultHandler.OAuthResultHandlerAdapter;
import org.scribe.model.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

import static org.apache.commons.lang3.StringUtils.removeStart;

public class DiscordHandler extends OAuthResultHandlerAdapter {
    private static final Gson GSON = new GsonBuilder().serializeNulls().create();

    private final OAuthRequestBuilder reqBuilder;
    private final String errorPage;
    private static final String provider = "oauth.discord";
    private static final String profileUrl = "https://discord.com/api/oauth2/@me";
    private static final Class<? extends RemoteUserProfile> profileClass = UserInfo.class;
    private static final String verifierParamName = "code";

    private final Users users;
    private final SessionHandler sessionHandler;

    private DiscordHandler(OAuthServiceBuilder serviceBuilder, OAuthRequestBuilder reqBuilder, String apiKey,
                           String apiSecret, String callback, Users users, SessionHandler sessionHandler, String errorPage) {
		super(  provider,//
				profileUrl,//
                profileClass, //
                verifierParamName,//
				users,//
				sessionHandler,//
				errorPage,//
				serviceBuilder.build(new Discord20Api(), apiKey, apiSecret, callback), reqBuilder);

        this.errorPage = errorPage;
        this.reqBuilder = reqBuilder;
        this.users = users;
        this.sessionHandler = sessionHandler;
	}

	private static class UserInfo implements RemoteUserProfile {
		String id;
        String displayName;

        @SerializedName("avatar")
        String avatar_hash;

        String email;

		@Override
		public boolean valid(Users users, String provider) {
			return users.userExistsAndEnabled(provider, id, displayName);
		}

		@Override
		public String username() {
			return id;
		}

        public String displayName() {
            return displayName;
        }
	}

	public static final OAuthResultHandlerFactory FACTORY = new OAuthResultHandlerFactory.Adapter() {

        @Override
        public OAuthResultHandler build(OAuthServiceBuilder serviceBuilder,
                OAuthRequestBuilder reqBuilder, OAuthProvider provider,
                String callback, Users users, SessionHandler sessionHandler,
                String errorPage) {
            return new DiscordHandler(serviceBuilder, reqBuilder, provider.getApiKey(), provider.getApiSecret(), callback, users, sessionHandler, errorPage);
        }

        @Override
        public boolean hasConfigurableBaseUrl() {
            return false;
        }
    };

    private String stateForAttribute() {
        return "EXPECTED_STATE_FOR_" + provider;
    }

    @Override
    public void handleCallback(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String state = (String) req.getSession().getAttribute(stateForAttribute());
        String reqUrl = (String) req.getSession().getAttribute("reqUrl-" + state);
        req.setAttribute("rememberMe", req.getSession().getAttribute("rememberMe-" + state));
        req.getSession().removeAttribute("reqUrl-" + state);
        req.getSession().removeAttribute("rememberMe-" + state);

        if (!validateStateParam(req)) {
            Redirector.sendRedirect(req, resp, req.getContextPath() + "/" + removeStart(errorPage, "/"), Collections.<String, List<String>> emptyMap());
            return;
        }

        // verify token
        Verifier verifier = new Verifier(req.getParameter(verifierParamName));
        Token accessToken = oauthService.getAccessToken(reqToken(req), verifier);

        // fetch user profile
        OAuthRequest oauthRequest = reqBuilder.req(Verb.GET, profileUrl);
        oauthService.signRequest(accessToken, oauthRequest);
        oauthRequest.addHeader("User-Agent", "Mozilla/5.0 (compatible; Lavagna/1.0; +https://lavagna.io)");
        Response oauthResponse = oauthRequest.send();
        JsonElement profileRoot = JsonParser.parseString(oauthResponse.getBody());
        final UserInfo profile;
        if ( profileRoot.isJsonObject() && ((JsonObject)profileRoot).get("user").isJsonObject() ) {
            JsonObject userObject = ((JsonObject)profileRoot).getAsJsonObject("user");
            UserInfo userInfoObj = new UserInfo();
            userInfoObj.avatar_hash = userObject.get("avatar").getAsString();
            userInfoObj.id = userObject.get("id").getAsString();
            if (userObject.has("email")) {
                userInfoObj.email = userObject.get("email").getAsString();
            }
            if (userObject.has("global_name")) {
                userInfoObj.displayName = userObject.get("global_name").getAsString();
            } else if (userObject.has("username")) {
                userInfoObj.displayName = userObject.get("username").getAsString();
            }

            profile = userInfoObj;
        } else {
            profile = null;
        }


        if ((profile != null) && profile.valid(users, provider)) {
            String url = Redirector.cleanupRequestedUrl(reqUrl, req);
            boolean userExists = users.userExistsAndEnabled(provider, profile.username(), profile.displayName()); //We need this to honor autocreation settings
            SecurityConfiguration.User user = users.findUserByName(provider, profile.username());

            sessionHandler.setUser(user.getId(), user.isAnonymous(), req, resp);
            Redirector.sendRedirect(req, resp, url, Collections.<String, List<String>> emptyMap());
        } else {
            Redirector.sendRedirect(req, resp, req.getContextPath() + "/" + removeStart(errorPage, "/"), Collections.<String, List<String>> emptyMap());
        }
    }
}
