const db = require('./db');
const conn = db.init();
const bcrypt = require('bcrypt');
const passport = require('passport');
const passportJWT = require('passport-jwt');
const JWTStrategy = passportJWT.Strategy;
const { ExtractJwt } = passportJWT;
const LocalStrategy = require('passport-local').Strategy;

db.connect(conn);

const LocalStrategyOption = {
    usernameField: "user_id",
    passwordField: "password"
};
async function localVerify(user_id, password, done){
    const user;
    try {
        const sql = 'select * from user where user_id = ?';
        const params = [user_id];
        await conn.query(sql, params, async function (err, row, fields){
            if(err){
                console.log(err);
                return done(null, false);
            }
            if(!row[0]) return done(null, false);
            user = row[0];

            console.log(password, user.password);
            const checkPassword = await bcrypt.compare(password, user.password);
            console.log(checkPassword);
            if(!checkPassword) return done(null, false);

            console.log(user);
            return done(null, user);
        })
    }catch(e){
        return done(e)
    }
}

const jwtStrategyOption = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: 'jwt-secret-key',
  };
  async function jwtVerift(payload, done) {
    var user;
    try {
      var sql = 'select * from user where user_id = ?';
      var params = [payload.user_id];
      await conn.query(sql, params, function (err, rows, fields) {
        if(!rows[0]) return done(null, false);
        user = rows[0];
  
        console.log(user);
        return done(null, user);
      });
    } catch (e) {
      return done(e);
    }
  }
  
  module.exports = () => {
    passport.use(new LocalStrategy(LocalStrategyOption, localVerify));
    passport.use(new JWTStrategy(jwtStrategyOption, jwtVerift));
  }