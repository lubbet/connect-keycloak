
module.exports = function(keycloak) {
  return function(request, response, next) {
    console.log("Grant attacher");
    keycloak.getGrant( request, response )
      .then( function(grant) {
        request.kauth.grant = grant;
      })
      .then( next )
      .catch( function(err) {
        console.log("Grant attacher error: " + err);
        next();
      } );
  };
};
