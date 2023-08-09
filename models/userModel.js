const crypto = require('crypto');
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "What's your name?"],
    },
    email: {
      type: String,
      required: [true, 'Please enter your email!'],
      unique: true,
      lowercase: true,
      validate: [validator.isEmail, 'Please enter a valid email'],
    },
    photo: {
      type: String,
      default: 'default.jpg',
    },
    role: {
      type: String,
      enum: ['user', 'guide', 'lead-guide', 'admin'],
      default: 'user',
    },
    password: {
      type: String,
      required: true,
      validate: [
        validator.isStrongPassword,
        'Please provide a strong password are length (the longer the better); a mix of letters (upper and lower case), numbers, and symbols.',
      ],
      select: false,
    },
    passwordConfirm: {
      type: String,
      required: true,
      validate: [
        // this only works on CREATE and SAVE
        function (el) {
          return el === this.password;
        },
        'The password confirmation does not match.',
      ],
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpiration: Date,
    active: {
      type: Boolean,
      default: true,
      select: false,
    },
  },
  {
    methods: {
      async correctPassword(candidatePassword, userPassword) {
        return await bcrypt.compare(candidatePassword, userPassword);
      },
      changePasswordAfter(JWTTimeStamp) {
        const changeTimeStamp = parseInt(
          this.passwordChangedAt.getTime() / 1000,
          10
        );
        return changeTimeStamp > JWTTimeStamp;
      },
      createPasswordResetToken() {
        const resetToken = crypto.randomBytes(32).toString('hex');

        this.passwordResetToken = crypto
          .createHash('sha256')
          .update(resetToken)
          .digest('hex');

        console.log({ resetToken }, this.passwordResetToken);

        this.passwordResetExpiration = Date.now() + 10 * 60 * 1000;

        return resetToken;
      },
    },
  }
);

userSchema.pre('save', async function (next) {
  // Only run this function if password was actually modified
  if (!this.isModified('password')) return next();

  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  // Delete passwordConfirm field
  this.passwordConfirm = undefined;
  next();
});

userSchema.pre('save', function (next) {
  if (!this.isModified || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;
  next();
});

userSchema.pre(/^find/, function (next) {
  this.find({ active: { $ne: false } });
  next();
});

const User = mongoose.model('User', userSchema);
module.exports = User;
