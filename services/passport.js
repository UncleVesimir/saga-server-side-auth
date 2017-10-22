const passort = require('passport'),
      User = require('../models/user'),
      config = require('../config'),
      mongoose = require('mongoose'),
      passport = require('passport'),
      JwtStrategy = require('passport-jwt').Strategy,
      ExtractJwt = require('passport-jwt').ExtractJwt,
      LocalStrategy = require('passport-local');

//usernameField tells passport to look at the email property passed in the request, as we are not using the
// default 'username'
const localOptions = {usernameField: "email"};
const localLogin = new LocalStrategy(localOptions, function(email, password, done){
  //here we need to validate that was is coming from the client request is valid to records on our 
  // database.
  User.findOne({email:email})
    .then( user => {
      if(!user){
        return done(null, false);
      }
      return user.comparePassword(password, function(err, isMatch){ //we use 'user', not 'User', as this
      // is the document with the method attached via mongoose!
        if(err){return done(err);}
        if(!isMatch){ return done(null, false)} // passing 'false' here causes passport to send a
        // default response of 401 - Unauthorized. This can be altered by passing a callback
        // to the authenticate middleware we set up, in router.js, which checks for the user == false,
        // and res.whatevers appropriately.
        return done(null, user)
      })
      // recall that our passwords have been hashed! So we need to use bcrypt salt + hash to compare against
      // a hashed version of the password supplied on sign in to verify the user.
     })
    .catch( err => done(err)) // general/ db query error catch
 })     



///JWT STRATEGY



// Set-up options for JWT strategy
// 'jwtFromRequest' property tells the strategy where to look for the JWT token on incoming requests.
// its value is a method that pulls the JWT from the request header, named - 'authorization'

//secretOrKey defines the private key we used to encrypt our token that was sent on sign-up or sign in.
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey : config.secret,

}
function buf2hex(buffer) { // buffer is an ArrayBuffer
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}
// Create JWT Strategy
//payload argument is the decoded JWT token, passed from the client. In this instance, it will be an object with a 'sub' property, that has a value of client id
// it will also include an 'issued at' property
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done){


  User.findById(buf2hex(payload.sub.data)) //payload will not be a valid ID if the JWT token is not legitimate
    .then( (authedUser) => {
      if (authedUser){
        done(null, authedUser); // passes to req.user if the decrypted JWT finds a valid ID.
      }
      else{
        done(null, false);  // in the instance that the JWT is decrypted, but the ID isn't valid.
        // i.e. not registered. - passport sees that req.user == false and prevents continuation of
        // router middleware chain and therefore preventing user access to certain pages.
      }
    })
    .catch( err => done(err, false));
    //general db error. - same as above, but passes error to next middleware for error information
})


passport.use(jwtLogin);
passport.use(localLogin);
// Tell Passport to use this strategy