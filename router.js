const Authentication = require("./controllers/authentication")
const passportService = require('./services/passport');
const passport = require('passport');

// Here the authenticate method is told to use the passport strategy JWT, which we setup in ../services/passport.js
// the first argument is referring to the name of the strategy that was set by the JWTStrategy library.
// the second argument instructs passport NOT to instantiate a cookie based session!
// basically this sets up the middleware to run through our JWT strategy which serialises the user to us
const requireAuth = passport.authenticate('jwt', {session: false}); 
const requireSignIn = passport.authenticate('local', {session: false}); 

module.exports = function(app) {
  app.get('/', requireAuth, function(req, res){
    res.send({message:"Super secret code is ABC123!"});
  })
  app.get('/pre-check_auth', requireAuth, function(req, res){
    res.json({tokenOK: true});
  })
  app.post('/signin', requireSignIn, Authentication.signin)
  app.post('/signup', Authentication.signup);

}
