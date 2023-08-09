const express = require('express');
const {
  checkoutSession,
  getAllBookings,
  createBookings,
  getBookings,
  updateBookings,
  deleteBookings,
} = require('../controllers/bookingController');

const { protect, restrictTo } = require('../controllers/authController');

const router = express.Router();

router.use(protect);
router.route('/checkout-session/:tourId').get(checkoutSession);
router.use(restrictTo('admin', 'lead-guide'));
router.route('/').get(getAllBookings, createBookings);

router
  .route('/:id')
  .get(getBookings)
  .patch(updateBookings)
  .delete(deleteBookings);

module.exports = router;
