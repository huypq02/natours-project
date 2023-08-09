const express = require('express');
const {
  getOverview,
  getTour,
  getLoginForm,
  getAccount,
  updateUserData,
  getMyTours,
} = require('../controllers/viewController');
const { isLoggedIn, protect } = require('../controllers/authController');
const { createBookingCheckout } = require('../controllers/bookingController');

const router = express.Router();

router.route('/').get(createBookingCheckout, isLoggedIn, getOverview);
router.route('/tour/:slug').get(isLoggedIn, getTour);
router.route('/login').get(isLoggedIn, getLoginForm);
router.route('/me').get(protect, getAccount);
router.route('/my-tours').get(protect, getMyTours);

router.route('/submit-user-data').post(protect, updateUserData);

module.exports = router;
