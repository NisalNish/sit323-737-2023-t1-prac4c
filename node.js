const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

const app = express();

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: 'Trymeout@2'
};

const jwtStrategy = new JwtStrategy(jwtOptions, (jwtPayload, done) => {
  if (jwtPayload && jwtPayload.sub) {
    return done(null, { id: jwtPayload.sub });
  } else {
    return done('Invalid token', false);
  }
});

passport.use(jwtStrategy);

const authenticate = passport.authenticate('jwt', { session: false });

const authorize = (req, res, next) => {
  if (req.user && req.user.isAdmin) {
    next();
  } else {
    res.status(403).send('Forbidden');
  }
};

app.get('/protected', authenticate, (req, res) => {
  res.send('Protected route');
});

app.get('/admin', authenticate, authorize, (req, res) => {
  res.send('Admin route');
});

app.listen(3040, () => {
  console.log('Server started on port 3040');
});
