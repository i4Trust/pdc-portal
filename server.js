var debug = require('debug')('portal:server');
const config = require('./config.js');
const moment = require('moment');
const uuid = require('uuid');
const fetch = require('node-fetch');
const jose = require('node-jose');
var jwt = require('jsonwebtoken').decode;
var bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const favicon = require('serve-favicon');
const express = require('express');
const { info } = require('console');
const request = require('request');
const qr = require('qrcode')
const session = require('express-session')
const app = express();


app.set('view engine', 'pug');
app.use(express.static(__dirname + '/public'));
app.use(favicon(path.join(__dirname, 'public/images', 'favicon.ico')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
	genid: function(req) {
	  return crypto.randomBytes(16).toString('hex')
	},
	secret: crypto.randomBytes(16).toString('hex'),
	// 5 min
	cookie: {
		maxAge: 5 * 60 * 1000
	  }

}))

// Global variables
global.portal_jwt = null;
global.user_idp = null;

// Prepare CRT
const crt_regex = /^-----BEGIN CERTIFICATE-----\n([\s\S]+?)\n-----END CERTIFICATE-----$/gm;
const chain = [];
let m;
while ((m = crt_regex.exec(config.crt)) !== null) {
    // This is necessary to avoid infinite loops with zero-width matches
    if (m.index === crt_regex.lastIndex) {
        crt_regex.lastIndex++;
    }
    chain.push(m[1].replace(/\n/g, ""));
}
debug('Prepared certificate chain: %o', chain);

// Create JWT
async function create_jwt(payload) {
    debug('Creating signed JWT for payload: %j', payload);
    const key = await jose.JWK.asKey(config.key, "pem");
    return await jose.JWS.createSign({
        algorithm: 'RS256',
        format: 'compact',
        fields: {
            typ: "JWT",
            x5c: chain
        }
    }, key).update(JSON.stringify(payload)).final();
}

// Send /authorise
async function authorise(idp) {
    debug('Perform /authorise for IDP: %j', idp);
    let result = {
	location: null,
	err: null
    };
    const now = moment();
    const iat = now.unix();
    const exp = now.add(30, 'seconds').unix();
    const token = await create_jwt({
	jti: uuid.v4(),
	iss: config.id,
	sub: config.id,
	aud: [
	    idp.id,
	    idp.token_endpoint
	],
	iat,
	nbf: iat,
	exp,
	response_type: "code",
	client_id: config.id,
	scope: "openid iSHARE sub name contact_details",
	redirect_uri: config.redirect_uri,
	state: "af0ifjsldkj",
	nonce: "c428224ca5a",
	acr_values: config.acr_values,
	language: "en"
    });
    portal_jwt = token;
    
    const params = new URLSearchParams();
    params.append('response_type', 'code');
    params.append('client_id', config.id);
    params.append('scope', 'iSHARE openid');
    params.append('request', token);

    
    try {
	debug('Sending /authorise request to IDP with URL encoded body: %o', params);
	const validation_response = await fetch(idp.authorize_endpoint, {
            method: 'POST',
            body: params,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
	});
	if (validation_response.status != 204 || !validation_response.headers.has('location')) {
	    debug('Invalid response on /authorise: %j', validation_response);
	    result.err = JSON.stringify(validation_response);
	} else {
	    debug('Received location header: %o', validation_response.headers.get('location'));
	    result.location = idp.url + validation_response.headers.get('location');
	}
	return result;
    } catch (e) {
	debug('Error: %o', e);
	result.err = e;
	return result;
    }
    
}

// Send /token
async function token(code, jwt, idp) {
    debug('Request /token at IDP');
    let result = {
	access_token: null,
	err: null
    };
    const tparams = new URLSearchParams();
    tparams.append('grant_type', 'authorization_code');
    tparams.append('client_id', config.id);
    tparams.append('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    tparams.append('client_assertion', jwt);
    tparams.append('redirect_uri', config.redirect_uri);
    tparams.append('code', code);

    try {
	debug('Sending request to /token endpoint of IDP with URL encoded params: %o', tparams);
	const token_response = await fetch(idp.token_endpoint, {
            method: 'POST',
            body: tparams
	});
	if (token_response.status != 200) {
	    debug('Request not successful: %j', token_response);
	    result.err = JSON.stringify(token_response);
	    return result;
	}
	
	const res_body = await token_response.json();
	if (!res_body) {
	    result.err = "Missing JSON response body";
	} else if (!res_body['access_token']) {
	    result.err = "Missing access_token in response body";
	} else {
	    debug('Received access token: %o', res_body['access_token']);
	    result.access_token = res_body['access_token']; 
	}
	return result;
    } catch (e) {
	result.err = e;
	return result;
    }
    
}

// GET delivery attributes
async function get_delivery(delivery_id, req_session) {
    let result = {
	err: null,
	delivery: null
    }
    var path = req_session.cb_endpoint + '/entities/' + delivery_id;
    var url = new URL(path);
    url.searchParams.append('options', 'keyValues');

    try {
	debug('Requesting data for delivery order at GET: %o', url.toString());
	const get_response = await fetch(url, {
	    method: 'GET',
	    headers: { 'Authorization': 'Bearer ' + req_session.access_token }
	});
	if (get_response.status != 200) {
	    const errorBody = await get_response.text();
	    result.err = `Access denied when retrieving delivery order: ${errorBody}`;
	    debug('Requesting delivery order data failed: %o', errorBody);
	    return result;
	}
	
	const res_body = await get_response.json();
	if (!res_body) {
	    result.err = "Missing JSON response body";
	} else {
	    debug('Received delivery order data: %j', res_body);
	    result.delivery = res_body; 
	}
	return result;
    } catch (e) {
	result.err = e;
	return result;
    }
    
}

// PATCH change delivery attribute
async function patch_delivery(id, attr, val, req_session) {
    let result = {
	err: null,
	status: null
    }
    var path = req_session.cb_endpoint + '/entities/' + id + '/attrs/' + attr;
    var url = new URL(path);
    const body = {
	type: "Property",
	value: val
    };

    try {
	debug('Perform PATCH request: Change ' + attr + ' to ' + val + ' for ' + id);
	debug('PATCH request URL: %o', url);
	debug('PATCH request body: %j', body);
	const patch_response = await fetch(url, {
	    method: 'PATCH',
	    headers: { 'Authorization': 'Bearer ' + req_session.access_token,
		       'Content-Type': 'application/json'
		     },
	    body: JSON.stringify(body)
	});
	if (patch_response.status != 204) {
	    const errorBody = await patch_response.text();
	    result.err = `Access denied when patching delivery order: ${errorBody}`;
	    debug('Received error when patching delivery order: %o', errorBody);
	    return result;
	}
	debug('PATCH successful');
	result.status = patch_response.status;
	return result;
    } catch (e) {
	result.err = e;
	return result;
    }
    
}

// Render error page
function render_error(res, user, error) {
    return res.render('error', {
	title: config.title,
	user: user,
	error: error
    });
}

// Obtain email parameter from JWT access_token of user
async function evaluate_user(req_session) {
    var user = null;
    if (req_session.access_token) {
	var decoded = jwt(req_session.access_token)
	user = decoded['email'];
    } 
    return user;
}

// Get SIOP flow QR code for login via mobile
function get_siop_qr(req) {
    let state = req.sessionID

    // Get redirect URI and DID
    const redirect_uri = config.siop.redirect_uri;
    const did = config.siop.did;

    // Further parameters
    const scope = config.siop.scope;
    const response_type = "vp_token";
    const response_mode = "post";

    // Build auth request
    let auth_request = "openid://?";
    auth_request += "scope="+scope;
    auth_request += "&response_type="+response_type;
    auth_request += "&response_mode="+response_mode;
    auth_request += "&client_id="+did;
    auth_request += "&redirect_uri="+redirect_uri;
    auth_request += "&state="+state;
    auth_request += "&nonce="+crypto.randomBytes(16).toString('base64');

	console.log(auth_request)

    return auth_request;
}


/*
  Routes
*/

// Main page
//
app.get('/', (req, res) => {
    debug('GET /: Call to main page');
    res.render('index', {
	title: config.title,
	idps: config.idp,
	siop: config.siop.enabled
    });
});

// /login
// Perform login by authorising and redirecting to login page of IDP
app.get('/login', async (req, res) => {
    debug('GET /login: Login requested');
    const idp = req.query.idp;
    const idp_config = config.idp.find(item => {return item.id == idp});
    user_idp = idp_config;
    const result = await authorise(idp_config);
    if (result.err) {
	render_error(res, null, '/authorise: ' + result.err)
    } else if (result.location) {
	debug('Perform redirect to: %o', result.location);
	res.redirect(result.location)
    } else {
	render_error(res, user, 'Failed authorisation')
    }
});

// Perform login via VC SIOP flow
app.get('/loginSiop', async (req, res) => {


    debug('GET /loginSiop: Login via VC requested');
	const qrcode = get_siop_qr(req)
	qr.toDataURL(qrcode, (err, src) => {
		res.render("siop",  {
			title: config.title,
			qr: src,
			verifierHost: config.siop.verifier_uri
			});
	})

});

app.get('/poll', async (req, res) => {

	info('Poll VC from ' + config.siop.verifier_uri );

		        // TODO:
		        // After retrieval of access token, store it in session with the correct CB host
		        // req.session.access_token = result.access_token;
		        // req.session.cb_endpoint = config.cb_endpoint_siop;
	
	if(Date.now() > req.session.cookie.expires) {
		res.send({data: "expired"})
	}
	request(config.siop.verifier_uri + "/verifier/api/v1/token/" + req.sessionID, function (error, response, body) {
		if (!error && response.statusCode == 200) {
			const token = body
		} 
	  })

	res.send({data: "pending"})
});

// /redirect
// Redirect endpoint for code flow
app.get(config.redirect_uri_path, async (req, res) => {
    debug('Receiving call to callback endpoint: %o', config.redirect_uri_path);
    if (!req.query || !req.query.code) {
	render_error(res, user, 'Did not receive authorisation code!')
    } else {
	const code = req.query.code;
	const result = await token(code, portal_jwt, user_idp);
	if (result.err) {
	    render_error(res, null, '/token: ' + result.err)
	    return;
	} else if (result.access_token) {
	    req.session.access_token = result.access_token;
	    req.session.cb_endpoint = config.cb_endpoint;
	    debug('Login succeeded, redirecting to /portal');
	    res.redirect('/portal');
	} else {
	    render_error(res, null, 'Failed retrieving token')
	    return;
	}
    }
    
});

// /logout
// Perform logout: Delete user token and redirect to main page
app.get('/logout', (req, res) => {
    req.session.access_token = null;
    req.session.destroy();
    res.redirect('/');
})

// GET /portal
// Display portal start page after login
app.get('/portal', async (req, res) => {
    debug('GET /portal: Call to portal page');
    var user = await evaluate_user(req.session);
    if (!user) {
	debug('User was not logged in');
	render_error(res, null, 'Not logged in');
	return;
    }
    
    res.render('portal', {
	title: config.title,
	delivery_id: '',
	user: user
    });
});

// POST /portal
// View/change  delivery order
app.post('/portal', async (req, res) => {
    debug('POST /portal: Updating portal page');
    var user = await evaluate_user(req.session);
    if (!user) {
	debug('User was not logged in');
	render_error(res, null, 'Not logged in');
	return;
    }
    
    const delivery_id = req.body.delivery_id;
    
    // Change attribute first if requested
    if (req.body.delivery_change_attr) {
	const change_attr = req.body.delivery_change_attr;
	const change_val = req.body.delivery_change_val;
	const patch_result = await patch_delivery(delivery_id, change_attr, change_val, req.session);
	if (patch_result.err) {
	    render_error(res, user, 'Failure patching delivery order: ' + patch_result.err)
	    return;
	}
    }
    
    // Get attributes of delivery ID
    const result = await get_delivery(delivery_id, req.session)
    if (result.err) {
	render_error(res, user, 'Failure retrieving delivery order: ' + result.err)
	return;
    }
    
    var delivery = null;
    if (result.delivery) {
	delivery = result.delivery;
    }

    debug('Render portal page for delivery order: %o', delivery_id);
    res.render('portal', {
	title: config.title,
	user: user,
	delivery_id: delivery_id,
	delivery: delivery
    });
});

// /health
// Healthcheck endpoint
app.get('/health', (req, res) => {
    res.send({
	uptime: process.uptime(),
	message: 'OK',
	timestamp: Date.now()
    });
})

// Start server
//
const server = app.listen(config.port, () => {
    console.log(`Express running → PORT ${server.address().port}`);
});

