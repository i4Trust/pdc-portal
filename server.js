const config = require('./config.js');
const moment = require('moment');
const uuid = require('uuid');
const fetch = require('node-fetch');
const jose = require('node-jose');
var jwt = require('jsonwebtoken').decode;
var bodyParser = require('body-parser');
const express = require('express');
const app = express();

app.set('view engine', 'pug');
app.use(express.static(__dirname + '/public'));
app.use(bodyParser.urlencoded({ extended: true }));

// Global variables
global.portal_jwt = null;
global.user_idp = null;
global.user_access_token = null;

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

// Create JWT
async function create_jwt(payload) {
    //console.log('Creating signed JWT for payload: ', JSON.stringify(payload));
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
    //console.log('/authorize: ' + JSON.stringify(idp));
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
	const validation_response = await fetch(idp.authorize_endpoint, {
            method: 'POST',
            body: params,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
	});
	if (validation_response.status != 204 || !validation_response.headers.has('location')) {
	    result.err = JSON.stringify(validation_response);
	} else {
	    result.location = idp.url + validation_response.headers.get('location');
	}
	return result;
    } catch (e) {
	result.err = e;
	return result;
    }
    
}

// Send /token
async function token(code, jwt, idp) {
    //console.log('/token');
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
	const token_response = await fetch(idp.token_endpoint, {
            method: 'POST',
            body: tparams
	});
	if (token_response.status != 200) {
	    result.err = JSON.stringify(token_response);
	    return result;
	}
	
	const res_body = await token_response.json();
	if (!res_body) {
	    result.err = "Missing JSON response body";
	} else if (!res_body['access_token']) {
	    result.err = "Missing access_token in response body";
	} else {
	    result.access_token = res_body['access_token']; 
	}
	return result;
    } catch (e) {
	result.err = e;
	return result;
    }
    
}

// GET delivery attributes
async function get_delivery(delivery_id) {
    let result = {
	err: null,
	delivery: null
    }
    var path = config.cb_endpoint + '/entities/' + delivery_id;
    var url = new URL(path);
    url.searchParams.append('options', 'keyValues');

    try {
	const get_response = await fetch(url, {
	    method: 'GET',
	    headers: { 'Authorization': 'Bearer ' + user_access_token }
	});
	if (get_response.status != 200) {
	    const errorBody = await get_response.text();
	    result.err = `Access denied when retrieving delivery order: ${errorBody}`;
	    return result;
	}
	
	const res_body = await get_response.json();
	if (!res_body) {
	    result.err = "Missing JSON response body";
	} else {
	    result.delivery = res_body; 
	}
	return result;
    } catch (e) {
	result.err = e;
	return result;
    }
    
}

// PATCH change delivery attribute
async function patch_delivery(id, attr, val) {
    let result = {
	err: null,
	status: null
    }
    var path = config.cb_endpoint + '/entities/' + id + '/attrs/' + attr;
    var url = new URL(path);
    const body = {
	type: "Property",
	value: val
    };

    try {
	const patch_response = await fetch(url, {
	    method: 'PATCH',
	    headers: { 'Authorization': 'Bearer ' + user_access_token,
		       'Content-Type': 'application/json'
		     },
	    body: JSON.stringify(body)
	});
	if (patch_response.status != 204) {
	    const errorBody = await patch_response.text();
	    result.err = `Access denied when patching delivery order: ${errorBody}`;
	    return result;
	}
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
async function evaluate_user() {
    var user = null;
    if (user_access_token) {
	var decoded = jwt(user_access_token)
	user = decoded['email'];
    } 
    return user;
}

/*
  Routes
*/

// Main page
//
app.get('/', (req, res) => {
    res.render('index', {
	title: config.title
    });
});

// /login
// Perform login by authorising and redirecting to login page of IDP
app.get('/login', async (req, res) => {
    const idp = req.query.idp;
    const idp_config = config.idp[idp]
    user_idp = idp_config;
    const result = await authorise(idp_config);
    if (result.err) {
	render_error(res, null, '/authorise: ' + result.err)
    } else if (result.location) {
	res.redirect(result.location)
    } else {
	render_error(res, user, 'Failed authorisation')
    }
});

// /redirect
// Redirect endpoint for code flow
app.get(config.redirect_uri_path, async (req, res) => {
    if (!req.query || !req.query.code) {
	render_error(res, user, 'Did not receive authorisation code!')
    } else {
	const code = req.query.code;
	const result = await token(code, portal_jwt, user_idp);
	if (result.err) {
	    render_error(res, null, '/token: ' + result.err)
	    return;
	} else if (result.access_token) {
	    user_access_token = result.access_token;
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
    user_access_token = null;
    res.redirect('/');
})

// GET /portal
// Display portal start page after login
app.get('/portal', async (req, res) => {

    var user = await evaluate_user();
    if (!user) {
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
    
    var user = await evaluate_user();
    if (!user) {
	render_error(res, null, 'Not logged in');
	return;
    }
    
    const delivery_id = req.body.delivery_id;
    
    // Change attribute first if requested
    if (req.body.delivery_change_attr) {
	const change_attr = req.body.delivery_change_attr;
	const change_val = req.body.delivery_change_val;
	console.log('Change ' + change_attr + ' to ' + change_val + ' for ' + delivery_id);
	const patch_result = await patch_delivery(delivery_id, change_attr, change_val);
	if (patch_result.err) {
	    render_error(res, user, 'Failure patching delivery order: ' + patch_result.err)
	    return;
	}
    }
    
    // Get attributes of delivery ID
    const result = await get_delivery(delivery_id)
    if (result.err) {
	render_error(res, user, 'Failure retrieving delivery order: ' + result.err)
	return;
    }
    console.log('Retrieved delivery order: ' + JSON.stringify(result.delivery));
    var delivery = null;
    if (result.delivery) {
	delivery = result.delivery;
    }
    
    res.render('portal', {
	title: config.title,
	user: user,
	delivery_id: delivery_id,
	delivery: delivery
    });
});

// Start server
//
const server = app.listen(config.port, () => {
    console.log(`Express running → PORT ${server.address().port}`);
});

