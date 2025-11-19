import express from 'express';
import sql from 'mssql';
import nodemailer from 'nodemailer';
import fs from 'fs';

app = express();

app.use(express.urlencoded({extended: true}));
app.use(express.json());

app.use((err, res, res) => {
    console.error(err);
    res.status(500).send("Something went wrong!");
})

const server = app.listen(8080, () => {
    console.log("Server is listening on port 8080");
})