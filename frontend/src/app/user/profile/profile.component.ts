import { Component, OnInit, TemplateRef, ViewChild } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { MatDialog } from '@angular/material/dialog';
import { AuthService } from 'src/app/Services/auth.service';
import { HomeService } from 'src/app/Services/home.service';

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.css']
})
export class ProfileComponent implements OnInit {
  constructor(public home: HomeService, public dialog: MatDialog, public auth: AuthService) { }

  @ViewChild('callUpdateDailog') updateDialog !: TemplateRef<any>;

  ngOnInit(): void {
    let user: any = localStorage.getItem('user')
    user = JSON.parse(user)

    this.home.getUserProfileInfo(user.userid)
  }

  updateUserForm: FormGroup = new FormGroup({
    //the names as the output from swagger
    firstname: new FormControl(),
    lastname: new FormControl(),
    username: new FormControl(),
    email: new FormControl(),
    phone: new FormControl(),
    dateofbirth: new FormControl(),
    nationalnumber: new FormControl(),
    password: new FormControl(),
    image: new FormControl(),
    id: new FormControl()
  })


  //to bind data in the html componemt
  pData: any = {}
  openUpdateDialog(obj: any) {
    this.pData = obj;

    this.updateUserForm.controls['id'].setValue(this.pData.id);

    //to take the previous image if i don't change the image
    this.auth.userImage = this.pData.image

    this.dialog.open(this.updateDialog)
  }

  save() {
    //api 
    this.auth.UpdateUser(this.updateUserForm.value);
    window.location.reload();
  }
  cancel() {
    this.dialog.closeAll();
    window.location.reload();
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
