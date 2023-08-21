import { showAlert } from './alerts.js';

export const bookTour = async (tourId) => {
  try {
    const res = await axios({
      url: `/api/v1/bookings/checkout-session/${tourId}`,
      method: 'get',
    });
    console.log(res);

    if (res.data.status === 'success') location.assign(res.data.session.url);
  } catch (err) {
    console.log(err);
    showAlert('error', err);
  }
};
