var debug = require('debug')('portal:config');
const fs = require('fs');
const yaml = require('js-yaml');

var user_cfg = {}
try {
    let config_file = './config/pdc-portal.yml';
    console.log("Loading config: ", config_file);
    let fileContents = fs.readFileSync(config_file, 'utf8');
    user_cfg = yaml.load(fileContents);
} catch (e) {
    console.error("Error loading pdc-portal.yml: ", e);
    process.exit(1)
}

let config = {};

// Default values
config.title = "Demo Portal";
config.getLabel = "Delivery Order";
config.inputLabel = "Packet Delivery ID";
config.key = "";
config.crt = "";
config.id = "EU.EORI.NLPACKETDEL";
config.port = 7000;
config.url = "http://localhost:7000";
config.redirect_uri_path = "/openid_connect1.0/return";
config.acr_values = "urn:http://eidas.europa.eu/LoA/NotNotified/high";
config.cb_endpoint = "https://localhost/ngsi-ld/v1";
config.idp = {}

// Title
if (user_cfg.title) {
    config.title = user_cfg.title;
}

// customization
if (user_cfg.getLabel) {
    config.getLabel = user_cfg.getLabel
}
if (user_cfg.inputLabel) {
    config.inputLabel = user_cfg.inputLabel
}

// Client data
if (user_cfg.client) {
    if (user_cfg.client.id) {
	config.id = user_cfg.client.id;
    }

    // Private key
    config.key = user_cfg.client.key;
    if (!!process.env.PORTAL_CLIENT_KEY) {
	config.key = process.env.PORTAL_CLIENT_KEY;
    }
    
    // Certificate chain
    config.crt = user_cfg.client.crt;
    if (!!process.env.PORTAL_CLIENT_CRT) {
	config.crt = process.env.PORTAL_CLIENT_CRT;
    }
}

// External access
if (user_cfg.external && user_cfg.external.host) {
    config.url = user_cfg.external.host;
}

// OIDC
if (user_cfg.oidc) {
    if (user_cfg.oidc.redirect_path) {
	config.redirect_uri_path = user_cfg.oidc.redirect_path;
    }
    if (user_cfg.oidc.acr) {
	config.acr_values = user_cfg.oidc.acr;
    }
}

// Context Broker
if (user_cfg.cb && user_cfg.cb.endpoint) {
    config.cb_endpoint = user_cfg.cb.endpoint;
}
if (user_cfg.cb && user_cfg.cb.endpoint_siop) {
    config.cb_endpoint_siop = user_cfg.cb.endpoint_siop;
}

// Web server
if (user_cfg.express && user_cfg.express.port) {
    config.port = user_cfg.express.port;
}

// Build external redirect URI
config.redirect_uri = config.url + config.redirect_uri_path;

// IDP
if (user_cfg.idp) {
    config.idp = user_cfg.idp;
}

// SIOP
config.siop = {
    clientId: user_cfg.siop.client_id,
    enabled: false,
    verifier_uri: user_cfg.siop.verifier_uri,
    login_path: "/api/v1/loginQR",
    token_path: "/token",
    jwtOnlyEnabled: false
}

if (user_cfg.siop && user_cfg.siop.enabled) {
    config.siop.enabled = true;
}

if (user_cfg.siop && user_cfg.siop.login_path) {
    config.siop.login_path = user_cfg.siop.login_path;
}

if (user_cfg.siop && user_cfg.siop.token_path) {
    config.siop.token_path = user_cfg.siop.token_path;
}

if (user_cfg.siop && user_cfg.siop.jwtOnlyEnabled) {
    config.siop.jwtOnlyEnabled = true;
}

// Debug output of config
debug('Loaded config: %O', config);

module.exports = config;
