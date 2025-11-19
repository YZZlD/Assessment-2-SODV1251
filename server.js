const express = require('express');
const sql = require('mssql');
const nodemailer = require('nodemailer');
const fs = require('fs');
const passport = require('passport');
const expressValidator = require('express-validator');
const LocalStrategy = require('passport-local');
const config = require('./config.js');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cors = require('cors');


const saltRounds = 10;

const app = express();
app.use(cors());

app.use(express.static('public'));

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
    console.log(user);
    console.log('PASSPORT MIDDLEWARE RUNNING.');
    
    if(!user) return done(null, false, {message: "Username not found."});
    
    await bcrypt.compare(password, user.Password, (err, result) => {
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

function isAuthenticated(req, res, next){
  if(req.isAuthenticated()) return next();
  res.status(401).json({message: "User not found."});
};

app.get('/login', async (req, res) => {
    res.sendFile(path.join(__dirname + '/public' + '/html' + '/login.html'));
});

app.post('/login', async (req, res) => {
    passport.authenticate('local', 
    {
        successRedirect: '/',
        failureRedirect: '/login',
    }), (req, res) => {
        console.log("FAILURE");
        res.redirect('login');
    }
});

app.get('/signup', async (req, res) => {
    res.sendFile(path.join(__dirname + '/public' + '/html' + '/signup.html'));
});

app.post('/signup', async (req, res) => {
    const {username, password} = req.body;
    const hashedPass = await bcrypt.hash(password, saltRounds);

    const pool = await poolPromise;
    const request = pool.request();

    request.input('username', sql.VarChar, username);
    request.input('password', sql.VarChar, hashedPass);
    
    await request.query("INSERT INTO Users (Username, Password) VALUES (@username, @password)");
});

app.get('/', isAuthenticated, async (req, res) => {
    const pool = await poolPromise;
    const result = await pool.query('SELECT * FROM Events');
    console.log(result);
    res.status(200).json(result.recordsets[0]);
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if(err) return res.send('Error logging out.');
    })
    res.send('Loggout out successfully. <a href="/login">Click here to login in again</a>');
})

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).send("Something went wrong!");
});

const server = app.listen(8080, () => {
    console.log("Server is listening on port 8080");
})