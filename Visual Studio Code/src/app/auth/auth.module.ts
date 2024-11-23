import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';  // Import this

import { AuthRoutingModule } from './auth-routing.module';
import { LoginComponent } from './login/login.component';
import { RegisterComponent } from './register/register.component';
import { ReactiveFormsModule } from '@angular/forms';
import { AirlineRegisterComponent } from './airline-register/airline-register.component';
import { AirlineLoginComponent } from './airline-login/airline-login.component';



@NgModule({
  declarations: [
    LoginComponent,
    RegisterComponent,
    AirlineRegisterComponent,
    AirlineLoginComponent
  ],
  imports: [
    CommonModule,
    AuthRoutingModule,
    ReactiveFormsModule,
    FormsModule
  ]
})
export class AuthModule { }
