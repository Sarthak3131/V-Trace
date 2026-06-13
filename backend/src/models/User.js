'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const userSchema = new mongoose.Schema(
	{
		name: {
			type: String,
			required: true,
			trim: true,
			minlength: 2,
			maxlength: 100,
		},
		email: {
			type: String,
			required: true,
			unique: true,
			lowercase: true,
			trim: true,
			match: EMAIL_REGEX,
		},
		password: {
			type: String,
			required: true,
			minlength: 8,
			select: false,
		},
		role: {
			type: String,
			enum: ['user', 'admin', 'moderator'],
			default: 'user',
		},
		isActive: {
			type: Boolean,
			default: true,
		},
		refreshTokens: {
			type: [String],
			default: [],
		},
		passwordChangedAt: {
			type: Date,
		},
	},
	{ timestamps: true }
);

userSchema.pre('save', async function hashPassword() {
	if (!this.isModified('password')) {
		return;
	}

	this.password = await bcrypt.hash(this.password, 12);
	this.passwordChangedAt = new Date();
});

userSchema.methods.comparePassword = async function comparePassword(candidatePassword) {
	return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.isPasswordChangedAfter = function isPasswordChangedAfter(jwtIssuedAt) {
	if (!this.passwordChangedAt) {
		return false;
	}

	const passwordChangedTimestamp = Math.floor(this.passwordChangedAt.getTime() / 1000);
	return passwordChangedTimestamp > jwtIssuedAt;
};

userSchema.statics.findByEmail = function findByEmail(email) {
	return this.findOne({ email: email.toLowerCase().trim() }).select('+password');
};

userSchema.index({ role: 1 });

module.exports = mongoose.models.User || mongoose.model('User', userSchema);
