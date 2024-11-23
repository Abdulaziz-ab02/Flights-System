import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginComponent } from './login/login.component';
import { RegisterComponent } from './register/register.component';
import { AirlineRegisterComponent } from './airline-register/airline-register.component';
import { AirlineLoginComponent } from './airline-login/airline-login.component';

const routes: Routes = [
  {
    path: 'login',
    component: LoginComponent
  },
  {
    path: 'register',
    component: RegisterComponent
  },
  {
    path: 'airlineregister',
    component: AirlineRegisterComponent
  },
  {
    path: 'airlinelogin',
    component: AirlineLoginComponent
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class AuthRoutingModule { }
