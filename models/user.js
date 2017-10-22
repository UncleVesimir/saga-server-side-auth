const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// Define our model
const userSchema = new Schema({
  email: { type: String, unique: true, lowercase: true },
  password: String
});

// Create the model class

//On Save Hook, encrypt password
userSchema.pre("save", function(next){
  const user = this;

  bcrypt.genSalt(10, function(err, salt){
    if(err) { return next(err);}

    bcrypt.hash(user.password, salt, null, function(err, hash){
      if(err){ return next(err); }

      user.password = hash;
      next();
    })
  })
})

userSchema.methods.comparePassword = function(candidatePassword, callback){
  // this.password is the password field on the current document being review
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch){
    if(err){
      return callback(err)
    }
    return callback(null, isMatch); //isMatch is either true or false, depending on comparison
  })
};

const ModelClass = mongoose.model('user', userSchema);



// Export the model
module.exports = ModelClass;
