import { Component } from '@angular/core';
import { FormControl, Validators } from '@angular/forms';
import { Router } from '@angular/router'; // Import the Router
import { AuthService } from 'src/app/Services/auth.service';


@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent {
  user_name: string = '';
  pass: string = '';
  rememberMe: boolean = false;

  constructor(private router: Router, private auth: AuthService) { }

  ngOnInit() {
    // Check if there is saved data in local storage
    const storedUsername = localStorage.getItem('username');
    const storedPassword = localStorage.getItem('password');

    if (storedUsername && storedPassword) {
      this.user_name = storedUsername;
      this.pass = storedPassword;
      this.rememberMe = true;  // Set 'Remember me' checkbox to checked
    }
  }



  username: FormControl = new FormControl('Your Username', Validators.required)
  password: FormControl = new FormControl('********', Validators.required)




  onSubmitLogin() {
    // Save the username and password in local storage
    if (this.rememberMe) {
      if (this.user_name && this.pass) {
        localStorage.setItem('username', this.user_name);
        localStorage.setItem('password', this.pass);
        console.log('Data saved in local storage');
      } else {
        console.log('Username or password is missing');
      }
    }
    this.auth.Login(this.username, this.password)

  }

}
