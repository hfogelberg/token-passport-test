var express = require('express'),
    bodyParser = require('body-parser'),
    jwt = require('jwt-simple'),
    auth = require('./auth')(),
    cfg = require('./config'),
    mongoose = require('mongoose'),
    User = require('./userModel'),
    bcrypt = require('bcrypt-nodejs'),
    app = express();

app.use(bodyParser.urlencoded({extended : true}));
app.use(auth.initialize());

// Handle CORS requests
app.use(function(req, res, next) {
	res.setHeader('Access-Control-Allow-Origin', '*');
	res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
	res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type, Authorization');
	next();
});

// Hook up to Db
mongoose.connect(cfg.db);
mongoose.connection.on('connected', function() {
  console.log('Mongoose connection open to ' + cfg.db);
});

app.get('/', function(req, res){
  res.json({message: 'API is alive'});
});

app.get('/user', auth.authenticate(), function(req, res){
  res.json(users(req.user.id));
});

// Sign up
app.post('/user', function(req, res){
  var user = new User({
    username: req.body.email,
    password: req.body.password
  });

  user.save(function(err){
      if(err) res.send(err);
      res.json({message: 'New user added'});
  })
})

// Log in and create token
app.post('/token', function(req, res){
  if(req.body.email && req.body.password){
    var email = req.body.email;
    var password = req.body.password;

    console.log('Email: ' + email);
    console.log('Received password: ' + password);

     User.findOne({username: email}, function(err, user){
       bcrypt.compare(password, user.password, function(err, isMatch){
         if(err) res.json({message: 'Error decrypting password ' + err});
         if(isMatch) {
           var payload = {id: user.id};
          var token = jwt.encode(payload, cfg.jwtSecret);
           res.json({message: 'Password OK', token: token});
         } else {
           res.json({message: 'Passwords do not match'});
         }
       });
     });
  } else {
    res.json({message: 'email or password missing'})
  }
});

app.listen(3000, function(){
  console.log('API is running on port 3000');
});

module.exports = app;
