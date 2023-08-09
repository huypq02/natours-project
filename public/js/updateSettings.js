// updateData
// import axios from 'axios'
import { showAlert } from './alerts.js';

//type is either 'password' or 'data'
export const updateSettings = async (data, type) => {
  try {
    const url =
      type === 'password'
        ? 'http://localhost:3333/api/v1/users/myPassword'
        : 'http://localhost:3333/api/v1/users/me';

    const res = await axios({
      method: 'PATCH',
      url,
      data,
    });

    if (res.data.status === 'success') {
      showAlert('success', `${type.toUpperCase()} updated successfully!`);
    }
  } catch (err) {
    // console.log(err);
    showAlert('error', err.response.data.message);
  }
};
