import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { AuthService } from 'src/app/Services/auth.service';

@Component({
  selector: 'app-airline-register',
  templateUrl: './airline-register.component.html',
  styleUrls: ['./airline-register.component.css']
})
export class AirlineRegisterComponent {

  constructor(private auth: AuthService) { }

  createAirlineForm = new FormGroup({
    airlinename: new FormControl('Your Name', Validators.required),
    airlineimage: new FormControl(),
    airlineemail: new FormControl('ex@example.com', [Validators.required, Validators.email]),
    airlineaddress: new FormControl(),
    activationstatus: new FormControl(),
    username: new FormControl('Your Username', Validators.required),
    password: new FormControl('*****', Validators.required),
    repeatPassword: new FormControl('*****', Validators.required),
    roleid: new FormControl()
  })

  matchError() {
    if (this.createAirlineForm.controls['password'].value ==
      this.createAirlineForm.controls['repeatPassword'].value
    )
      this.createAirlineForm.controls['repeatPassword'].setErrors(null)
    else
      this.createAirlineForm.controls['repeatPassword'].setErrors({ misMatch: true })
  }


  submit() {
    this.createAirlineForm.controls['roleid'].setValue(3);
    this.createAirlineForm.controls['activationstatus'].setValue('Pending');
    this.auth.CreateAirline(this.createAirlineForm.value)
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
    this.auth.uploadAttachmentAirline(formData);

  }
}
