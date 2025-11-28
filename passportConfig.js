const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const sql = require('mssql');
const config = require('./config');

const poolPromise = new sql.ConnectionPool(config)
    .connect()
    .then(pool => {
        console.log('Connected to MSSQL');
        return pool;
    })
    .catch(err => console.log('Database connection failed:', err));

passport.use(new LocalStrategy(async (username, password, done) => {
    try {
        const pool = await poolPromise;
        const request = pool.request();
        request.input('username', sql.VarChar, username);
        const result = await request.query('SELECT * FROM Users WHERE Username = @username');

        if (result.recordset.length === 0) {
            return done(null, false, { message: 'User not found' });
        }

        const user = result.recordset[0];
        const isValid = await bcrypt.compare(password, user.Password);

        if (!isValid) {
            return done(null, false, { message: 'Incorrect password' });
        }

        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.Id);
});

passport.deserializeUser(async (Id, done) => {
    try {
        const pool = await poolPromise;
        const request = pool.request();
        request.input('Id', sql.Int, Id);
        const result = await request.query('SELECT * FROM Users WHERE Id = @Id');

        if (result.recordset.length === 0) {
            return done(null, false);
        }

        return done(null, result.recordset[0]);
    } catch (err) {
        return done(err);
    }
});

module.exports = passport;
