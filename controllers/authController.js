const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');

const signToken = id => {
  return jwt.sign({ id: id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
    passwordChangedAt: req.body.passwordChangedAt
  });
  console.log(newUser);

  const token = signToken(newUser._id);

  res.status(201).json({
    status: 'success',
    token,
    data: {
      user: newUser
    }
  });
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1 check if email and password exist
  if (!email || !password) {
    return next(new AppError('please provide email and/or password', 400));
  }

  // 2 check if user exists
  const user = await User.findOne({ email: email }).select('+password');

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }

  // if okay, send token
  const token = signToken(user._id);
  res.status(200).json({
    status: 'success',
    token
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  // 1) Get the token and check if it exists
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }
  // console.log(token);

  if (!token) {
    return next(
      new AppError('You are not logged-in; log-in to get access', 401)
    );
  }
  // 2) Verification token

  const decodedJwtToken = await promisify(jwt.verify)(
    token,
    process.env.JWT_SECRET
  );
  console.log(decodedJwtToken);

  // 3) Check if user still exists
  const currentUser = await User.findById(decodedJwtToken.id);
  if (!currentUser) {
    return next(new AppError('The user of this token no longer exists', 401));
  }

  // 4) check if user changed passwords after JWT was issued

  if (currentUser.changedPasswordAfter(decodedJwtToken.iat)) {
    return next(
      new AppError(
        'User has recently changed the password - need to login again',
        401
      )
    );
  }
  req.user = currentUser;
  next();
});
