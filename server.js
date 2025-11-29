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
const EventEmitter = require('events')

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

const eventAddedEmitter = new EventEmitter();

eventAddedEmitter.on('eventAdded', (data) => {
    console.log(data.email);
    let message = {
        from: 'Angelina Botsford <angelina.botsford@ethereal.email>',
        to: `${data.username} <${data.email}>`,
        subject: 'Event creation confirmation',
        text: `Hello ${data.username}.\nThank you for creating ${data.eventName}. Your event is scheduled for ${new Date(data.eventDateTime).toLocaleString()} at ${data.eventLocation}.`
    };

    transporter.sendMail(message, (err, info) => {
        if(err) {
            console.log('Error occured. ' + err.message);
        }
    })
});

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
    if(req.isAuthenticated()) return res.send('Currently logged in.');
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

app.post('/signup', [validator.check('username').isLength({min: 5}).withMessage("Username must be at least 5 characters."), validator.check('password').isLength({min: 5}).withMessage("Password must be at least 5 characters."), validator.check('email').isEmail().withMessage('Please enter a valid email.')], async (req, res) => {
    try {
        const errors = validator.validationResult(req);
        if(!errors.isEmpty()) return res.status(400).json({errors: errors.array()})
        const { username, password, email } = req.body;

        const hashedPass = await bcrypt.hash(password, saltRounds);
        const pool = await poolPromise;
        const request = pool.request();

        request.input('username', sql.VarChar, username);
        request.input('password', sql.VarChar, hashedPass);
        request.input('email', sql.VarChar, email);

        await request.query('INSERT INTO Users (Username, Password, Email) VALUES (@username, @password, @email)');
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

app.get('/events', isAuthenticated, async(req, res) => {
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
                <div style="position: relative; border: solid 1px #ddd; padding: 10px; display: flex; flex-direction: column; align-items: center;">
                    <h1 style="font-size: 18px; text-align: center;">${event.EventName}</h1>
                    <h2 style="font-size: 14px; text-align: center;">${event.EventDateTime}</h2>
                    <h3 style="font-size: 14px; text-align: center;">${event.EventLocation}</h3>
                    <p style="font-size: 14px; text-align: center;">${event.EventDescription}</p>
                    <img src="uploads/${event.EventImageSrc}" style="width: 100%; height: auto; max-width: 500px; max-height: 200px" alt="Event Image">
                    <p style="position: absolute; top: 0px; left: 10px; font-size: 12px; color: #555;">Event ID: ${event.Id}</p>
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

app.get('/createEvent', isAuthenticated, async(req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'html/createEvent.html'));
});

app.post('/createEvent', isAuthenticated, upload.single('eventImage'), async (req, res) => {
    try{
        const { eventName, eventDateTime, eventLocation, eventDescription } = req.body;
        const pool = await poolPromise;
        const request = pool.request();
        request.input('EventName', sql.VarChar, eventName);
        request.input('EventDateTime', sql.DateTime, eventDateTime);
        request.input('EventLocation', sql.VarChar, eventLocation);
        request.input('EventDescription', sql.VarChar, eventDescription);
        request.input('EventImageSrc', sql.VarChar, req.file.originalname);

        await request.query('INSERT INTO Events (EventName, EventDateTime, EventLocation, EventDescription, EventImageSrc) VALUES (@EventName, @EventDateTime, @EventLocation, @EventDescription, @EventImageSrc)');
        eventAddedEmitter.emit('eventAdded', {username: req.user.Username, eventName: eventName, eventDateTime: eventDateTime, eventLocation: eventLocation, email: req.user.Email});
        res.status(201).redirect('/events');
    }catch(err)
    {
        res.status(500).json({message: "Error while creating event."})
    }
});

app.put('/events/:id', async(req, res) => {
    try{
        const { eventName, eventDateTime, eventLocation, eventDescription} = req.body;
        console.log(eventName, eventDateTime, eventLocation, eventDescription);

        const pool = await poolPromise;
        const request = pool.request();

        request.input('EventName', sql.VarChar, eventName);
        request.input('EventDateTime', sql.DateTime, eventDateTime);
        request.input('EventLocation', sql.VarChar, eventLocation);
        request.input('EventDescription', sql.VarChar, eventDescription);
        request.input('Id', sql.Int, req.params.id);
        await request.query(`UPDATE Events SET EventName = @EventName, EventDateTime = @EventDateTime, EventLocation = @EventLocation, EventDescription = @EventDescription WHERE Id = @Id`);

        res.status(204).json({ message: "Successfully updated event." })
    }catch(err)
    {
        res.status(500).json({ message: "Error while updating event." })
    }


});

app.delete('/events/:id', isAuthenticated, async(req, res) => {
    try{
        const pool = await poolPromise;
        await pool.query(`DELETE FROM Events WHERE Id = ${req.params.id}`);

        res.status(204).json({ message: 'Event deleted successfully.' });
    }catch(err)
    {
        res.status(500).json({ message: 'Error while deleting event.' });
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
