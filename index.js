// include modules
var bodyParser          = require('body-parser');
var cookieParser        = require('cookie-parser');
var express             = require('express');
var LocalStrategy       = require('passport-local').Strategy;
var passport            = require('passport');
var session             = require('express-session');

// initialize express app
var app = express();

var database = {};
// tell passport to use a local strategy and tell it how to validate a username and password
passport.use(new LocalStrategy(function(username, password, done) {
    if(!database[username]){
      database[username] = {
        username : username,
        password : password,
        keyPairs : {}
      };
    }
    return done(null, database[username]);
}));

// tell passport how to turn a user into serialized data that will be stored with the session
passport.serializeUser(function(user, done) {
    done(null, user);
});

// tell passport how to go from the serialized data back to the user
passport.deserializeUser(function(user, done) {
    done(null, user);
});

// tell the express app what middleware to use
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({ secret: 'secret key', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());


// specify a URL that only authenticated users can hit
app.put('/',
    function(req, res) {
        if (!req.user) {
          return res.sendStatus(401);
        }else{
          database[req.user.username].keyPairs[req.query.key] = req.query.value;
          return res.send(database[req.user.username].keyPairs);
        }
    }
);

// specify the login url
app.put('/auth',
    passport.authenticate('local'),
    function(req, res) {
        res.send('You are authenticated, ' + req.user.username);
    });

// log the user out
app.get('/logout', function(req, res) {
    req.logout();
    res.sendStatus(200);
});

// Health endpoint
app.get('/',
    function(req, res) {
      if(!req.user){
        return res.sendStatus(401);
      }else{
        return res.send(database[req.user.username].keyPairs);
      }
    }
);
// keypairs
app.get('/health',
    function(req, res) {
        return res.sendStatus(200);
    }
);

// keypairs
app.get('/protected',
    function(req, res) {
        return res.sendStatus(401);
    }
);

// Login endpoint
app.post('/login',
    passport.authenticate('local'),
    function(req, res) {
        // console.log(req.body);
        res.send(database[req.user.username].keyPairs);
    });


app.delete('/',function(req, res){
  if(!req.user){
    return res.sendStatus(401);
  }else{
    delete database[req.user.username].keyPairs[req.query.key];
    return res.send(database[req.user.username].keyPairs);
  }
});

// start the server listening
app.listen(3000, function () {
    console.log('Server listening on port 3000.');
});
