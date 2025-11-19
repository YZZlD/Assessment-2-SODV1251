require('dotenv').config();

const config = {
    user: process.env.USER,
    password: process.env.PASSWORD,
    server: process.env.SERVER || 'localhost',
    database: process.env.DATABASE,
    options: {
        encrypt: false,
        trustServerCertificate: true
    }
};

module.exports = config;