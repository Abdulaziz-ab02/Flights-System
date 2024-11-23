import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { ToastrService } from 'ngx-toastr';
import { AdminService } from 'src/app/Services/admin.service';
import { HomeService } from 'src/app/Services/home.service';

@Component({
  selector: 'app-contactus',
  templateUrl: './contactus.component.html',
  styleUrls: ['./contactus.component.css']
})
export class ContactusComponent implements OnInit {
  constructor(public home: HomeService, public admin: AdminService,
    private toastr: ToastrService
  ) { }

  ngOnInit(): void {
    this.home.getContactInfo()
  }


  ContactMessagesForm: FormGroup = new FormGroup({
    firstname: new FormControl('', Validators.required),
    lastname: new FormControl('', Validators.required),
    email: new FormControl('', Validators.required),
    message: new FormControl('', Validators.required)
  })

  SendMessage() {
    this.admin.CreateContactMessage(this.ContactMessagesForm.value).subscribe(
      res => {
        console.log("ContactMessage created")
        this.ContactMessagesForm.reset()
        this.toastr.success("Message Sent!")
      },
      err => {
        this.toastr.error("Error sending message!");
        console.log("error creating ContactMessage")
      }
    )
  }

}
