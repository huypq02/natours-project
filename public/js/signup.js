/* eslint-disable */
// import axios from 'axios';
import { showAlert } from './alerts.js';

export const signup = async (email, password, passwordConfirm) => {
  try {
    const res = await axios({
      method: 'post',
      url: '/api/v1/users/signup',
      data: {
        email: email,
        password: password,
        passwordConfirm: passwordConfirm,
      },
    });

    if (res.data.status === 'success') {
      showAlert('success', 'Signed up successfully!');
      window.setTimeout(() => {
        location.assign('/');
      }, 1500);
    }
  } catch (err) {
    showAlert('error', err.response.data.message);
  }
};
