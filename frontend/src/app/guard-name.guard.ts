import { CanActivateFn, Router } from '@angular/router';
import { inject } from '@angular/core';
import { ToastrService } from 'ngx-toastr';

export const guardNameGuard: CanActivateFn = (route, state) => {
  const router = inject(Router);
  let toastr: ToastrService = inject(ToastrService);
  const token = localStorage.getItem('token');


  const messageShown = sessionStorage.getItem('messageShown');

  if (token) {
    let user: any = localStorage.getItem('user');
    if (user) {
      user = JSON.parse(user);


      if (state.url.includes('admin/viewprofile')) {
        if (user.roleid === '1' || user.roleid === '3') {
          if (!messageShown) {
            toastr.success('Welcome to the Profile page');
            sessionStorage.setItem('messageShown', 'true');
          }
          return true;
        } else {
          toastr.warning('This page is restricted');
          router.navigate(['security/login']);
          return false;
        }
      }



      if (state.url.indexOf('admin') > 0) {
        if (user.roleid === '1') {
          if (!messageShown) {
            toastr.success('Welcome to Admin dashboard');
            sessionStorage.setItem('messageShown', 'true');
          }
          return true;
        } else {
          toastr.warning('This page is for Admin module');
          router.navigate(['security/login']);
          return false;
        }
      }

      if (state.url.indexOf('user') > 0) {
        if (user.roleid === '2') {
          if (!messageShown) {
            toastr.success('Welcome to User dashboard');
            sessionStorage.setItem('messageShown', 'true');
          }
          return true;
        } else {
          toastr.warning('This page is for User module only');
          router.navigate(['security/login']);
          return false;
        }
      }

      if (state.url.indexOf('airline') > 0) {
        if (user.roleid === '3') {
          if (!messageShown) {
            toastr.success('Welcome to Airline dashboard');
            sessionStorage.setItem('messageShown', 'true');
          }
          return true;
        } else {
          toastr.warning('This page is for Airline module only');
          router.navigate(['security/login']);
          return false;
        }
      }
    }
    return false;
  } else {
    toastr.warning('Please sign up');
    router.navigate(['security/register']);
    return false;
  }
};
