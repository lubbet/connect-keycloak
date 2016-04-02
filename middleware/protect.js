var UUID = require('./../uuid' );

function forceLogin(keycloak, request, response) {
  var host = request.hostname;
  var headerHost = request.headers.host.split(':');
  var port = headerHost[1] || '';
  var protocol = request.protocol;

  var redirectUrl = protocol + '://' + host + ( port == '' ? '' : ':' + port ) + request.url + '?auth_callback=1';

  request.session.auth_redirect_uri = redirectUrl;

  var uuid = UUID();
  var loginURL = keycloak.loginUrl( uuid, redirectUrl );
  response.redirect( loginURL );
}

function simpleGuard(role,token) {
  if ( role.indexOf( "app:" ) === 0 ) {
    return token.hasApplicationRole( role.substring( 4 ) );
  }
  if ( role.indexOf( "realm:" ) === 0 ) {
    return token.hasRealmRole( role.substring( 6 ) );
  }

  return false;
}

module.exports = function(keycloak, spec) {

  var guard;

  if ( typeof spec == 'function' ) {
    guard = spec;
  } else if ( typeof spec == 'string' ) {
    guard = simpleGuard.bind(undefined, spec);
  }

  return function(request, response, next) {
    console.log("KC Protect (" + spec + "): " + request.url);

    if ( request.kauth && request.kauth.grant ) {
      console.log("KCP Has grant");
      if ( ! guard || guard( request.kauth.grant.access_token, request, response ) ) {
        return next();
      }

      console.log("KCP accessDenied");
      return keycloak.accessDenied(request,response,next);
    }

    if (keycloak.config.bearerOnly){
      console.log("Bearer only, no access");
      return keycloak.accessDenied(request,response,next);
    }else{
      console.log("No auth data, forcing login");
      forceLogin(keycloak, request, response);
    }

  };
};
