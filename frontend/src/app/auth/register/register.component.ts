import { Component } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { ToastrService } from 'ngx-toastr';
import { AuthService } from 'src/app/Services/auth.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent {

  constructor(private auth: AuthService,
    private toastr: ToastrService
  ) { }


  createUserForm: FormGroup = new FormGroup({
    //the names as the output from swagger
    firstname: new FormControl('Your First Name', Validators.required),
    lastname: new FormControl('Your Last Name', Validators.required),
    username: new FormControl('Your Username', Validators.required),
    email: new FormControl('ex@example.com', [Validators.required, Validators.email]),
    phone: new FormControl(),
    dateofbirth: new FormControl(),
    nationalnumber: new FormControl('Your National Number', Validators.required),
    password: new FormControl('********', Validators.required),
    repeatPassword: new FormControl('********', Validators.required),
    image: new FormControl(),
    roleid: new FormControl()
  })

  matchError() {
    if (this.createUserForm.controls['password'].value ==
      this.createUserForm.controls['repeatPassword'].value
    )
      this.createUserForm.controls['repeatPassword'].setErrors(null)
    else
      this.createUserForm.controls['repeatPassword'].setErrors({ misMatch: true })
  }

  submit() {
    const username = this.createUserForm.controls['username'].value;
    const email = this.createUserForm.controls['email'].value;

    this.auth.CheckUserExists(username, email).subscribe(
      (response) => {
        // Check the response, e.g., 'username' or 'email' or 'none'
        if (response.result === 'username') {
          // Show an error for username
          this.toastr.error('Username already exists.', 'Error');
        } else if (response.result === 'email') {
          // Show an error for email
          this.toastr.error('Email already exists.', 'Error');
        } else {
          // Continue with form submission if neither exists
          this.createUserForm.controls['roleid'].setValue(2);
          this.auth.CreateUser(this.createUserForm.value);
        }
      },
      (error) => {
        // Handle error if the request fails
        console.error('Error checking user existence', error);
      }
    );

    // this.createUserForm.controls['roleid'].setValue(2);
    // this.auth.CreateUser(this.createUserForm.value)
  }


  uploadImage(file: any) {
    //no image uploaded
    if (file.length == 0)
      return;

    //take first image (if user uploaded multiple images)
    let fileToUpload = <File>file[0];

    //trun to formdata so the func in service accept it
    const formData = new FormData();
    formData.append('file', fileToUpload, file.name)
    this.auth.uploadAttachmentUser(formData);

  }


}
