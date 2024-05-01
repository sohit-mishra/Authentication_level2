const mongoose = require('mongoose');
require('dotenv').config();

const URL =  process.env.MONGODBURI;

const connectToDatabase = ()=>{
    mongoose.connect(URL).then(()=>{
        console.log('Connect to Database');
    }).catch((error)=>{
        console.log(error);
    })
}

module.exports = connectToDatabase;
