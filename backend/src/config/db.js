'use strict';

const mongoose = require('mongoose');
const { MONGO_URI } = require('./env');

async function connectDB() {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('MongoDB Connected');
  } catch (error) {
    console.error('MongoDB connection error:', error.message);
    process.exit(1);
  }
}

module.exports = connectDB;
