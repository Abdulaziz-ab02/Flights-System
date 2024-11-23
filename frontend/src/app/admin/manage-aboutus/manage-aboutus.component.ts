import { Component, OnInit, TemplateRef, ViewChild } from '@angular/core';
import { HomeService } from 'src/app/Services/home.service';
import { MatButtonModule } from '@angular/material/button';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { AdminService } from 'src/app/Services/admin.service';
import { MatDialog } from '@angular/material/dialog';



@Component({
  selector: 'app-manage-aboutus',
  templateUrl: './manage-aboutus.component.html',
  styleUrls: ['./manage-aboutus.component.css']
})
export class ManageAboutusComponent implements OnInit {
  constructor(public home: HomeService,
    public admin: AdminService,
    public dialog: MatDialog) { }

  @ViewChild('callUpdateDailog') updateDialog !: TemplateRef<any>;

  ngOnInit(): void {
    this.home.getAboutInfo()
  }

  updateAboutForm: FormGroup = new FormGroup({
    abouttitle: new FormControl('', Validators.required),
    aboutcontent: new FormControl('', Validators.required),
    aboutimage: new FormControl(''),
    id: new FormControl()
  })

  pData: any = {}
  openUpdateDialog(obj: any) {
    this.pData = obj;

    this.updateAboutForm.controls['id'].setValue(this.pData.id);
    this.admin.aboutImage = this.pData.aboutimage;
    this.dialog.open(this.updateDialog)
  }

  save() {
    this.admin.UpdateAboutInfo(this.updateAboutForm.value)
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
    this.admin.uploadAttachmentAbout(formData);
  }

}
