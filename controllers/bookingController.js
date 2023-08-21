const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const Tour = require('../models/tourModel');
const Booking = require('../models/bookingModel');
const catchAsync = require('../utils/catchAsync');
const {
  deleteOne,
  updateOne,
  createOne,
  getOne,
  getAll,
} = require('./handlerFactory');

exports.checkoutSession = catchAsync(async (req, res) => {
  //1) Get the currently booked tour
  const tour = await Tour.findById(req.params.tourId);

  //2) Create checkout session
  const session = await stripe.checkout.sessions.create({
    customer_email: req.user.email,
    client_reference_id: req.params.tourId,
    line_items: [
      {
        price_data: {
          // The currency parameter determines which
          // payment methods are used in the Checkout Session.
          product_data: {
            name: `${tour.name} Tour`,
            description: tour.summary,
            images: [`http://localhost:3333/img/tours/${tour.imageCover}`],
          },
          unit_amount: tour.price * 100,
          currency: 'usd',
        },
        quantity: 1,
      },
    ],
    mode: 'payment',
    success_url: `${req.protocol}://${req.get('host')}/?tour=${
      req.params.tourId
    }&user=${req.user.id}&price=${tour.price}`,
    cancel_url: `${req.protocol}://${req.get('host')}/tour/${tour.slug}`,
  });

  // 3) Create session as response
  res.status(200).json({
    status: 'success',
    session,
  });

  // console.log(session.url);
  // // res.redirect(session.url);

  // res
  //   .writeHead(302, {
  //     Location: `${session.url}`,
  //   })
  //   .end();
});

exports.createBookingCheckout = catchAsync(async (req, res, next) => {
  // This is only TEMPORARY, because it's UNSECURE: everyone can make bookings with paying
  const { tour, user, price } = req.query;

  if (!tour && !user && !price) return next();
  await Booking.create({ tour, user, price });

  res.redirect(req.originalUrl.split('?')[0]);
});

exports.getAllBookings = getAll(Booking);
exports.getBookings = getOne(Booking);
exports.createBookings = createOne(Booking);
exports.updateBookings = updateOne(Booking);
exports.deleteBookings = deleteOne(Booking);
