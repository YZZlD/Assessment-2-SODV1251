const express = require('express');
const sql = require('mssql');
const nodemailer = require('nodemailer');
const fs = require('fs');
const passport = require('passport');
const bcrypt = require('bcrypt');
const expressValidator = require('express-validator');
const LocalStrategy = require('passport-local');
const config = require('./config.js');
const session = require('express-session');



const app = express();

app.use(express.urlencoded({extended: true}));
app.use(express.json());

app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  //cookie: { secure: false} //For production
  cookie: { secure: false ,httpOnly: false} // For development only
}));

app.use(passport.initialize());
app.use(passport.session());

const poolPromise = new sql.ConnectionPool(config)
    .connect()
    .then(pool => {
        console.log('Connected to MSSQL');
        return pool;
    })
    .catch(err => console.log('Database connection failed! Bad config: ', err));

passport.use(new LocalStrategy(async (username, password, done) => {
    const pool = await poolPromise;
    const user = await pool.query(`SELCT * FROM Users WHERE Username == ${username}`).recordsets[0];
    
    if(!user) return done(null, false, {message: "Username not found."});
    
    bcrypt.compare(password, user.Password, (err, result) => {
        if(err) throw err;
        if(result) return done(null, user);
        return done(null, false, {message: "Incorrect password."});
    });
}));

passport.serializeUser((user, done) => {
    done(null, user.username);
});

passport.deserializeUser(async (username, done) => {
    const pool = await poolPromise;
    const deserializedUser = await pool.query(`SELECT * FROM Users WHERE Username == ${username}`).recordsets[0];
    if(!deserializedUser) return done('User not found', null);
    return done(null, deserializedUser);
});

app.get('/', async (req, res) => {
    const pool = await poolPromise;
    const result = await pool.query('SELECT * FROM Events');
    console.log(result);
    res.status(200).json(result.recordsets[0]);
});

app.get('/login', async (req, res) => {

});

app.get('/signup', async (req, res) => {

});

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).send("Something went wrong!");
})

const server = app.listen(8080, () => {
    console.log("Server is listening on port 8080");
})