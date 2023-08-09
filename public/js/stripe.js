import { showAlert } from './alerts.js';

export const bookTour = async (tourId) => {
  try {
    const res = await axios({
      url: `http://localhost:3333/api/v1/bookings/checkout-session/${tourId}`,
      method: 'get',
    });

    if (res.data.status === 'success') location.assign(res.data.session.url);
  } catch (err) {
    console.log(err);
    showAlert('error', err);
  }
};
