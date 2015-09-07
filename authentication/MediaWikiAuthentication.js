/**
 * Script to authenticate on a MediaWiki site in ZAP.
 *
 * MediaWiki protects against Login CSRF using a login token generated
 * on viewing the login page and storing it in the session and in a
 * hidden field in the login form. On submitting the login form, the
 * submitted token and the one in the session are compared to prevent
 * login CSRF. So, we need to first get the login token and session
 * cookie, then use those to perform the login request.
 *
 * The required parameter 'Login URL' should be set to the path to
 * Special:UserLogin, i.e. http://127.0.0.1/wiki/Special:UserLogin
 *
 * The regex pattern to identify logged in responses could be set to:
 *     id="pt-logout"
 *
 * The regex pattern to identify logged out responses could be set to:
 *     id="pt-login"
 *
 * @author grunny
 */

function authenticate(helper, paramsValues, credentials) {
	println("Authenticating via JavaScript script...");
	importClass(org.parosproxy.paros.network.HttpRequestHeader);
	importClass(org.parosproxy.paros.network.HttpHeader);
	importClass(org.apache.commons.httpclient.URI);
	importClass(net.htmlparser.jericho.Source);

	var authHelper = new MWAuthenticator(helper, paramsValues, credentials),
		sessionData = authHelper.getSessionData();

	return authHelper.doLogin(sessionData);
}

function getRequiredParamsNames(){
	return ['Login URL'];
}

function getOptionalParamsNames(){
	return ['Session cookie name'];
}

function getCredentialsParamsNames(){
	return ['Username', 'Password'];
}

function MWAuthenticator(helper, paramsValues, credentials) {
	this.helper = helper;
	this.loginUrl = paramsValues.get('Login URL');
	this.sessionCookieName = paramsValues.get('Session cookie name');
	this.userName = credentials.getParam('Username');
	this.password = credentials.getParam('Password');

	if (this.sessionCookieName.isEmpty()) {
		this.sessionCookieName = 'wiki_session';
	}

	return this;
}

MWAuthenticator.prototype = {
	doLogin: function (sessionData) {
		var requestBody = 'wpName=' + encodeURIComponent(this.userName) +
				'&wpPassword=' + encodeURIComponent(this.password) +
				'&wpLoginToken=' + encodeURIComponent(sessionData.loginToken),
			response = this.doRequest(
				this.loginUrl + (this.loginUrl.indexOf('?') > -1 ? '&' : '?') + 'action=submitlogin&type=login',
				HttpRequestHeader.POST,
				requestBody,
				sessionData.sessionCookie
			);

		return response;
	},

	getSessionData: function () {
		var sessionCookie,
			response = this.doRequest(this.loginUrl, HttpRequestHeader.GET),
			sessionCookieValue = this.getSessionCookieValue(response, this.sessionCookieName),
			loginToken = this.getLoginToken(response, 'wpLoginToken');

		sessionCookie = this.sessionCookieName + '=' + sessionCookieValue + '; HttpOnly';

		return { 'sessionCookie': sessionCookie, 'loginToken': loginToken };
	},

	doRequest: function (url, requestMethod, requestBody, cookie) {
		var msg,
			requestInfo,
			requestUri = new URI(url, false);
			requestHeader = new HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP10);

		if (cookie) {
			requestHeader.setHeader(HttpHeader.COOKIE, cookie);
		}

		requestInfo = 'Sending ' + requestMethod + ' request to ' + requestUri;
		msg = this.helper.prepareMessage();
		msg.setRequestHeader(requestHeader);

		if (requestBody) {
			requestInfo += ' with body: ' + requestBody;
			msg.setRequestBody(requestBody);
		}

		println(requestInfo);
		this.helper.sendAndReceive(msg);
		println("Received response status code for authentication request: " + msg.getResponseHeader().getStatusCode());

		return msg;
	},

	getSessionCookieValue: function (request, cookieName) {
		var cookie, iterator, cookieValue,
			cookies = request.getResponseHeader().getCookieParams();

		for (iterator = cookies.iterator(); iterator.hasNext();) {
			cookie = iterator.next();
			if (cookie.getName() == cookieName) {
				cookieValue = cookie.getValue();
				break;
			}
		}

		return cookieValue;
	},

	getLoginToken: function (request, loginTokenName) {
		var iterator, element, loginToken,
			pageSource = request.getResponseHeader().toString() + request.getResponseBody().toString(),
			src = new Source(pageSource),
			elements = src.getAllElements('input');

		for (iterator = elements.iterator(); iterator.hasNext();) {
			element = iterator.next();
			if (element.getAttributeValue('name') == 'wpLoginToken') {
				loginToken = element.getAttributeValue('value');
				break;
			}
		}

		return loginToken;
	}
};
