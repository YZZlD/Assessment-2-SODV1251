const express = require('express');
const sql = require('mssql');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const config = require('./config.js');
const validator = require('express-validator')

const saltRounds = 10;
const app = express();

// Middleware
app.use(cors({
    origin: 'http://localhost:8080',
    credentials: true
}));
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session Configuration
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true }
}));

// Passport Configuration
app.use(passport.initialize());
app.use(passport.session());

// Database Pool
const poolPromise = new sql.ConnectionPool(config)
    .connect()
    .then(pool => {
        console.log('Connected to MSSQL');
        return pool;
    })
    .catch(err => console.log('Database connection failed:', err));

// Passport Local Strategy
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

// Serialize User
passport.serializeUser((user, done) => {
    done(null, user.Id);
});

// Deserialize User
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

// Middleware: Check Authentication
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(401).json({ message: 'Not authenticated' });
}

// Routes
app.get('/', (req, res) => {
    res.json({
        message: 'AUTH SERVER',
        authenticated: req.isAuthenticated(),
        user: req.user || null
    });
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

// Error Handler
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ message: 'Server error', error: err.message });
});

const PORT = 8080;
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
