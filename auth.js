var passport = require("passport"),
    passportJWT = require("passport-jwt"),
    users = require("./userModel"),
    cfg = require("./config"),
    ExtractJwt = passportJWT.ExtractJwt,
    Strategy = passportJWT.Strategy,
    params = {
      secretOrKey: cfg.jwtSecret,
      jwtFromRequest: ExtractJwt.fromAuthHeader()
    };

module.exports = function() {
  var strategy = new Strategy(params, function(payload, done) {
    var user = users[payload.id] || null;
    if (user) {
      return done(null, {id: user.id});
    } else {
      return done(new Error("User not found"), null);
    }
  });

  passport.use(strategy);
  return {
    initialize: function() {
      return passport.initialize();
    },
    authenticate: function() {
      return passport.authenticate("jwt", cfg.jwtSession);
    }
  };
};
