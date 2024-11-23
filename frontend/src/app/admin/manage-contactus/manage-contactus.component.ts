import { Component, OnInit, TemplateRef, ViewChild } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { MatDialog } from '@angular/material/dialog';
import { AdminService } from 'src/app/Services/admin.service';
import { HomeService } from 'src/app/Services/home.service';

@Component({
  selector: 'app-manage-contactus',
  templateUrl: './manage-contactus.component.html',
  styleUrls: ['./manage-contactus.component.css']
})
export class ManageContactusComponent implements OnInit {
  constructor(public home: HomeService,
    public admin: AdminService,
    public dialog: MatDialog
  ) { }

  @ViewChild('callUpdateDailog') updateDialog !: TemplateRef<any>;

  ngOnInit(): void {
    this.home.getContactInfo()
  }


  updateContactForm: FormGroup = new FormGroup({
    contactemail: new FormControl('', Validators.required),
    contactphone: new FormControl('', Validators.required),
    contactaddress: new FormControl('', Validators.required),
    id: new FormControl()
  })

  pData: any = {}
  openUpdateDialog(obj: any) {
    this.pData = obj;

    this.updateContactForm.controls['id'].setValue(this.pData.id);
    this.dialog.open(this.updateDialog)
  }

  save() {
    this.admin.UpdateContactInfo(this.updateContactForm.value)
  }

}
