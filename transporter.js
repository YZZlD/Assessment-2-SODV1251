const nodemailer = require('nodemailer')

nodemailer.createTestAccount((err, account) => {
    if(err){
        console.error('Feailed to create a testing account. ' + err.message);
    }

    console.log('Credentials obtained, sending message...');
});

const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
        user: 'angelina.botsford@ethereal.email',
        pass: 'tV6bBsQJ9EDym2cgWg'
    }
});

module.exports = transporter;
