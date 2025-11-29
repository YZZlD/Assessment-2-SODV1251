const express = require('express');
const sql = require('mssql');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const config = require('./config.js');
const validator = require('express-validator')
const transporter = require('./transporter.js')
const passport = require('./passportConfig.js')
const upload = require('./upload.js');

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
    res.redirect('/login');
}

app.get('/', async (req, res) => {
    res.redirect('/events')
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html/login.html'));
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
            res.redirect('/events');
        });
    })(req, res, next);
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html/signup.html'));
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

app.get('/events', async(req, res) => {
    try{
        const pool = await poolPromise;
        const events = await pool.query('SELECT * FROM Events');

        let eventList = `
        <html>
            <body>
                <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 20px; padding: 20px;">
        `;

        events.recordset.forEach(event => {
            eventList += `
                <div style="border: solid 1px #ddd; padding: 10px; display: flex; flex-direction: column; align-items: center;">
                    <h1 style="font-size: 18px; text-align: center;">${event.EventName}</h1>
                    <h2 style="font-size: 14px; text-align: center;">${event.EventDateTime}</h2>
                    <h3 style="font-size: 14px; text-align: center;">${event.EventLocation}</h3>
                    <p style="font-size: 14px; text-align: center;">${event.EventDescription}</p>
                    <img src="uploads/cat.png" style="width: 100%; height: auto; max-width: 500px; max-height: 200px" alt="Event Image">
                </div>
            `;
        });
        //
        eventList += `
                </div>
            </body>
        </html>
        `;

        res.send(`${eventList}`);


    }catch(err){
        res.status(500).json({message: 'Error getting events.'});
    }
});

app.get('/events/:id', isAuthenticated, async(req, res) => {
    try{
        const pool = await poolPromise;
        const request = pool.request();
        request.input('id', sql.Int, req.params.id);

        const result = await request.query('SELECT * FROM Events WHERE Id = @id');


        if(result.recordset.length == 0)
        {
            res.status(400).json({message: 'Event could not be found.'});
        }
        const event = result.recordset[0];
        res.status(200).json(event);
    }catch(err) {
        res.status(500).json({message: 'Error getting event.'});
    }
});



app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ message: 'Server error', error: err.message });
});

const PORT = 8080;
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
