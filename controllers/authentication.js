const User = require('../models/user');
const jwt = require('jwt-simple');
const config = require('../config')

function tokenForUser(user){
  return jwt.encode({ sub:user.id }, config.secret)
}


exports.signup = function (req, res, next){

  const email = req.body.email;
  const password = req.body.password;

  if(!email || !password){
    res.status(422).send({error:"You must provide an email and a password"});
  }

  User.findOne({email: email}).then((user) => {
    if(user){
      res.status(422);
      res.send({error: "Email is already in use."})
    }
    else{
      User.create({email:email, password:password}) //user model as pre-save hook that encrypts password before saving
        .then( () => res.json( {sigupSuccess: true} ) )
        .catch( err =>   next(err))
    }
  }).catch( err => next(err) );
}

exports.signin = function(req, res, next){
 res.send({token:tokenForUser(req.user._id)});
}
