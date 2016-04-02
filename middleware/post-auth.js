var URL = require('url');

module.exports = function(keycloak) {
  return function(request, response, next) {
    if ( ! request.query.auth_callback ) {
      return next();
    }

    console.log("Keycloak post-auth middleware");

    if ( request.query.error ) {
      console.log("KC PA Query error: " + request.query.error);
      return keycloak.accessDenied(request,response,next);
    }

    keycloak.getGrantFromCode( request.query.code, request, response )
      .then( function(grant) {
        console.log("KC PA Got grant: " + JSON.stringify(grant));

        var urlParts = {
          pathname: request.path,
          query: request.query,
        };

        delete urlParts.query.code;
        delete urlParts.query.auth_callback;
        delete urlParts.query.state;

        var cleanUrl = URL.format( urlParts );
        console.log("cleanUrl: " + cleanUrl);
        
        request.kauth.grant = grant;
        try {
          keycloak.authenticated( request );
        } catch (err) {
          console.log( err );
        }
        response.redirect( cleanUrl );
      });
  };
};