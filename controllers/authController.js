const { promisify } = require('util');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

// Passport supports for Google OAuth 2.0
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20');

const catchAsync = require('../utils/catchAsync');
const User = require('../models/userModel');
const AppError = require('../utils/appError');
const Email = require('../utils/email');

const signToken = function (id) {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user.id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

  res.cookie('jwt', token, cookieOptions);
  user.password = undefined;

  if (res.req.url.includes('/oauth2/redirect/google')) return res.redirect('/');

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user: user,
    },
  });
};

// Configure the GoogleStrategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: '/api/v1/users/oauth2/redirect/google',
      scope: ['profile', 'email'],
      session: false, // Disable session request
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const existingUser = await User.findOne({ email: profile.id }).exec();
        // console.log(existingUser);
        if (existingUser) {
          return cb(null, existingUser);
        }
        // console.log('profile', profile.photos[0]);
        const user = await new User({
          email: profile.id,
          name: profile.displayName,
          photo: profile.photos[0].value,
        }).save();
        cb(null, user);
      } catch (err) {
        cb(err, null);
      }
    }
  )
);

// Configure JWT strategy
passport.use(
  new JwtStrategy(
    {
      secretOrKey: process.env.JWT_SECRET, // The same key used to sign the token
      jwtFromRequest: ExtractJwt.fromExtractors([
        // Use a custom extractor function
        function (req) {
          // Define the extractor function
          if (req && req.headers && req.headers.cookie) {
            // Check if the request has a cookie header
            const cookies = req.headers.cookie.split(';'); // Split the cookie header by semicolons

            for (let cookie of cookies) {
              // Loop through each cookie
              cookie = cookie.trim(); // Remove any whitespace
              if (cookie.startsWith('jwt=')) {
                // Check if the cookie name is jwt
                return cookie.slice(4); // Return the cookie value without the jwt= prefix
              }
            }
          }
          return null; // Return null if no jwt cookie is found
        },
      ]), // Extract token from header
    },
    (jwtPayload, done) =>
      // Here you can find or verify a user in your database
      // For simplicity, we just return the payload object
      done(null, jwtPayload)
  )
);

// Redirect to Google
exports.redirectToGoogle = passport.authenticate('google');

// Redirect back to app
exports.redirectBackToApp = passport.authenticate('google', {
  failureRedirect: '/login',
  session: false,
});

exports.loginByGoogleAuth = catchAsync(async (req, res, next) => {
  createSendToken(req.user, 201, res);
});

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create(req.body);

  const url = `${req.protocol}://${req.get('host')}/me`;
  // console.log(url);
  await new Email(newUser, url).sendWelcome();

  createSendToken(newUser, 201, res);
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  // 1. Check if email and password exists
  if (!email || !password) {
    return next(new AppError('Please provide email and password!', 400));
  }

  // 2. Check if user exist && password is correct
  const user = await User.findOne({ email: email }).select('+password').exec();

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Invalid email or password', 400));
  }
  // 3. If everything ok, send token to client
  createSendToken(user, 200, res);
});

exports.logout = (req, res, next) => {
  if (req.cookies.jwt) {
    res.cookie('jwt', 'loggedout', {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true,
    });
  } else {
    // Log out passport Google OAuth 2.0
    req.logout((err) => {
      if (err) {
        return next(new AppError(err, 400));
      }
    });
  }

  res.status(200).json({ status: 'success' });
};

exports.protect = catchAsync(async (req, res, next) => {
  // 1. Getting token and check of it's there
  let token = '';
  console.log(req.headers);
  if (req.headers.authorization?.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return next(
      new AppError("You're not logged in! Please log in to gain access!", 401)
    );
  }
  // 2. Verification token
  const verify = promisify(jwt.verify);
  const decoded = await verify(token, process.env.JWT_SECRET);

  // 3. Check if user still exists
  const currentUser = await User.findById(decoded.id).exec();
  if (!currentUser) {
    return next(
      new AppError('The user belonging to this token no longer exist!', 401)
    );
  }

  // 4. Check if user changed password after the token was issued
  if (currentUser.changePasswordAfter(decoded.iat)) {
    return next(
      new AppError('User recently changed password! Please login again.', 401)
    );
  }

  // GRANT ACCESS TO PROTECTED ROUTE
  req.user = currentUser;
  // THERE IS A LOGGED IN USER
  res.locals.user = currentUser;

  next();
});

// Only for rendered page, no errors!
exports.isLoggedIn = async (req, res, next) => {
  if (req.cookies.jwt) {
    try {
      // 1. Verify token
      const verify = promisify(jwt.verify);
      const decoded = await verify(req.cookies.jwt, process.env.JWT_SECRET);

      // 2. Check if user still exists
      const currentUser = await User.findById(decoded.id).exec();
      if (!currentUser) {
        return next();
      }

      // 3. Check if user changed password after the token was issued
      if (currentUser.changePasswordAfter(decoded.iat)) {
        return next();
      }

      // THERE IS A LOGGED IN USER
      res.locals.user = currentUser;

      return next();
    } catch (err) {
      return next();
    }
  }
  next();
};

exports.restrictTo = function (...roles) {
  return (req, res, next) => {
    // roles ['admin', 'lead-guide']
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action!', 403)
      );
    }
    next();
  };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1. Get user based on POSTed email
  const user = await User.findOne({ email: req.body.email }).exec();
  if (!user) {
    return next(new AppError('There is no user with email address.', 404));
  }

  // 2. Generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  try {
    // 3. Send it to user's email
    const resetUrl = `${req.protocol}://${req.get(
      'host'
    )}/api/v1/users/resetPassword/${resetToken}`;

    await new Email(user, resetUrl).sendPasswordReset();

    res.status(200).json({
      status: 'success',
      message: 'Token sent to email',
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpiration = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
      new AppError(
        'There was an error sending the email. Try again later!',
        500
      )
    );
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpiration: { $gt: Date.now() },
  }).exec();
  // 2) If token has not expired, and there is user, set the new password
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpiration = undefined;

  await user.save();

  // 3) Update changePasswordAt property for the user

  // 4) Log the user in, send JWT
  createSendToken(user, 200, res);
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  // 1) Get user from collection
  const user = await User.findById(req.user.id).select('+password').exec();

  // 2) Check if POSTed current password is correct
  if (
    !user ||
    !(await user.correctPassword(req.body.passwordCurrent, user.password))
  ) {
    return next(new AppError('Invalid email or password', 400));
  }

  // 3) If so, update password
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();
  // 4) Log user in, send JWT
  createSendToken(user, 200, res);
});
