const express = require('express');
const sql = require('mssql');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const config = require('./config.js');
const validator = require('express-validator')
const transporter = require('./transporter')
const passport = require('./passportConfig')

const saltRounds = 10;
const app = express();

app.use(cors({
    origin: 'http://localhost:8080',
    credentials: true
}));

app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true }
}));

app.use(passport.initialize());
app.use(passport.session());

const poolPromise = new sql.ConnectionPool(config)
    .connect()
    .then(pool => {
        console.log('Connected to MSSQL');
        return pool;
    })
    .catch(err => console.log('Database connection failed:', err));

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(401).json({ message: 'Not authenticated' });
}

app.get('/', async (req, res) => {
    res.json({
        message: 'AUTH SERVER',
        authenticated: req.isAuthenticated(),
        user: req.user || null
    });

    let message = {
        from: 'Sender Name <sender@example.com>',
        to: 'Recipient <recipient@example.com>',
        subject: 'Nodemailer is unicode friendly ✔',
        text: 'Hello to myself!',
        html: '<p><b>Hello</b> to myself!</p>'
    }
    await transporter.sendMail(message, (err, info) => {
        if(err) {
            console.log('Error occured. ' + err.message);
        }

        console.log('Message sent: %s', info.messageId);
        console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));
    })
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return res.status(500).json({ message: 'Server error' });
        }
        if (!user) {
            return res.status(401).json({ message: info?.message || 'Authentication failed' });
        }
        req.logIn(user, (err) => {
            if (err) {
                return res.status(500).json({ message: 'Login failed' });
            }
            return res.json({ message: 'Login successful', user: req.user });
        });
    })(req, res, next);
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.post('/signup', [validator.check('username').isLength({min: 5}), validator.check('password').isLength({min: 5})], async (req, res) => {
    try {
        const errors = validator.validationResult(req);
        if(!errors.isEmpty()) return res.status(400).json({errors: errors.array()})
        const { username, password } = req.body;

        const hashedPass = await bcrypt.hash(password, saltRounds);
        const pool = await poolPromise;
        const request = pool.request();

        request.input('username', sql.VarChar, username);
        request.input('password', sql.VarChar, hashedPass);

        await request.query('INSERT INTO Users (Username, Password) VALUES (@username, @password)');
        res.status(201).json({ message: 'User created successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Signup failed', error: err.message });
    }
});

app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).json({ message: 'Logout failed' });
        }
        res.json({ message: 'Logged out successfully' });
    });
});

app.get('/profile', isAuthenticated, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ message: 'Server error', error: err.message });
});

const PORT = 8080;
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
