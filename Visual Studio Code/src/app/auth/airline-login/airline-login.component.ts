import { Component } from '@angular/core';
import { FormControl, Validators } from '@angular/forms';
import { AuthService } from 'src/app/Services/auth.service';

@Component({
  selector: 'app-airline-login',
  templateUrl: './airline-login.component.html',
  styleUrls: ['./airline-login.component.css']
})
export class AirlineLoginComponent {
  constructor(public auth: AuthService) { }


  username: FormControl = new FormControl('Your Username', Validators.required)
  password: FormControl = new FormControl('********', Validators.required)

  onSubmitLogin() {
    this.auth.AirlineLogin(this.username, this.password)
  }



}
