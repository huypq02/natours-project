// review / rating / createAt / ref to tour / ref to user
const mongoose = require('mongoose');
const Tour = require('./tourModel');
// const AppError = require('../controllers/errorController');

const reviewSchema = new mongoose.Schema(
  {
    review: {
      type: String,
      required: [true, 'Review can not be empty'],
    },
    rating: {
      type: Number,
      min: 1,
      max: 5,
    },
    createAt: {
      type: Date,
      default: Date.now(),
    },
    tour: {
      type: mongoose.Schema.ObjectId,
      ref: 'Tour',
      required: [true, 'Review must belongs to a tour'],
    },
    user: {
      type: mongoose.Schema.ObjectId,
      ref: 'User',
      required: [true, 'Review must belongs to a user'],
      validate: [
        async function (value) {
          const isDuplicate = await this.isDuplicate();
          return !isDuplicate;
        },
        'Duplicate review',
      ],
    },
  },
  {
    methods: {
      async isDuplicate() {
        const existingReview = await this.model('Review').findOne({
          tour: this.tour,
          user: this.user,
        });
        return !!existingReview;
      },
    },
    statics: {
      async calcAverageRatings(tourId) {
        const stats = await this.aggregate([
          {
            $match: { tour: tourId },
          },
          {
            $group: {
              _id: '$tour',
              nRating: { $sum: 1 },
              avgRating: { $avg: '$rating' },
            },
          },
        ]);
        console.log(stats);
        if (stats.length > 0) {
          await Tour.findByIdAndUpdate(tourId, {
            ratingsQuantity: stats[0].nRating,
            ratingsAverage: stats[0].avgRating,
          });
        } else {
          await Tour.findByIdAndUpdate(tourId, {
            ratingsQuantity: 0,
            ratingsAverage: 4.5,
          });
        }
      },
    },
  }
);

// reviewSchema.index({ tour: 1, user: 1 }, { unique: true});

reviewSchema.pre(/^find/, function (next) {
  this.populate({
    path: 'user',
    select: 'name photo',
  });
  next();
});

reviewSchema.post('save', function () {
  // this point to current review
  console.log(this.constructor);
  if (this.constructor) this.constructor.calcAverageRatings(this.tour);
});

reviewSchema.post(/^findOneAnd/, async function (doc) {
  this.r = doc;
  console.log(this.r);

  await this.r.constructor.calcAverageRatings(this.r.tour);
});

const Review = mongoose.model('Review', reviewSchema);

module.exports = Review;
