/* eslint-disable */
// import axios from 'axios';
import { showAlert } from './alerts.js';

export const login = async (email, password) => {
  // console.log('LOGIN!!!');
  // console.log(email, password);
  try {
    const res = await axios({
      method: 'post',
      url: '/api/v1/users/login',
      data: {
        email: email,
        password: password,
      },
    });

    if (res.data.status === 'success') {
      showAlert('success', 'Logged in successfully!');
      window.setTimeout(() => {
        location.assign('/');
      }, 1500);
    }
  } catch (err) {
    showAlert('error', err.response.data.message);
  }
};

export const logout = async () => {
  try {
    const res = await axios({
      method: 'get',
      url: '/api/v1/users/logout',
    });
    if (res.data.status === 'success') location.assign('/');
  } catch (err) {
    showAlert('error', 'Error logging out! Try again!');
  }
};
