import { writable } from 'svelte/store';
import Cookies from 'js-cookie';
const tokenFromCookie = Cookies.get('token');
console.log(tokenFromCookie);
const tokenStore = writable(tokenFromCookie ? JSON.parse(tokenFromCookie) : null);
tokenStore.subscribe(value => {
  Cookies.set('token', JSON.stringify(value), { expires: null });
});
export default tokenStore;
